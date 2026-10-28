//! Where a virtual-media image comes from: a local file, or an HTTP(S) URL.
//!
//! Every family's media path is a target that answers the BMC's block reads,
//! so all it needs is `Read + Seek` over the image. A URL is read with ranged
//! GETs — this client fetches, then serves the bytes down the same outbound
//! connection a local file would use. That is the proxy path: it works for
//! every family and asks nothing of the BMC's own network, which is why it is
//! what `mount <url>` falls back to when a BMC cannot fetch a URL itself.
//!
//! Reads are served from a read-ahead window, because the BMCs ask in 2-128K
//! pieces and a request per piece would cost a round trip each.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::time::Duration;

/// How much to fetch per request. Large enough that a sequential install
/// streams at link speed, small enough that a random seek stays cheap.
const WINDOW: u64 = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

/// True when `spec` names a URL rather than a file.
pub fn is_url(spec: &str) -> bool {
    let s = spec.trim_start().to_ascii_lowercase();
    s.starts_with("http://") || s.starts_with("https://")
}

/// The last path segment, without a query string — for status lines and the
/// drive-type decision (which goes by extension).
pub fn file_name(spec: &str) -> String {
    let s = spec.split(['?', '#']).next().unwrap_or(spec);
    let s = s.trim_end_matches(['/', '\\']);
    s.rsplit(['/', '\\']).next().unwrap_or(s).to_string()
}

pub enum Source {
    File(std::fs::File),
    Http(Box<Http>),
}

impl Source {
    /// Open a file read-only, or a URL.
    pub fn open(spec: &str) -> std::io::Result<Source> {
        if is_url(spec) {
            Ok(Source::Http(Box::new(Http::open(spec.trim())?)))
        } else {
            Ok(Source::File(std::fs::File::open(spec)?))
        }
    }

    /// Open read-write where that is possible — a local file the user may
    /// write. Returns the source and whether writes will land.
    pub fn open_rw(spec: &str) -> std::io::Result<(Source, bool)> {
        if !is_url(spec) {
            if let Ok(f) = std::fs::OpenOptions::new().read(true).write(true).open(spec) {
                return Ok((Source::File(f), true));
            }
        }
        Ok((Source::open(spec)?, false))
    }

    pub fn len(&self) -> std::io::Result<u64> {
        match self {
            Source::File(f) => Ok(f.metadata()?.len()),
            Source::Http(h) => Ok(h.size),
        }
    }
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Source::File(f) => f.read(buf),
            Source::Http(h) => h.read(buf),
        }
    }
}

impl Seek for Source {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Source::File(f) => f.seek(pos),
            Source::Http(h) => h.seek(pos),
        }
    }
}

impl Write for Source {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Source::File(f) => f.write(buf),
            Source::Http(_) => Err(ioerr("a URL image is read-only")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Source::File(f) => f.flush(),
            Source::Http(_) => Ok(()),
        }
    }
}

// ---------- HTTP ----------

struct Url {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(u: &str) -> std::io::Result<Url> {
    let (tls, rest) = if let Some(r) = strip_prefix_ci(u, "https://") {
        (true, r)
    } else if let Some(r) = strip_prefix_ci(u, "http://") {
        (false, r)
    } else {
        return Err(ioerr("only http:// and https:// URLs are supported"));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        return Err(ioerr("credentials in the URL are not supported"));
    }
    let default = if tls { 443 } else { 80 };
    // [v6]:port, host:port, or a bare host.
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let end = r.find(']').ok_or_else(|| ioerr("malformed IPv6 address in URL"))?;
        let port = r[end + 1..].strip_prefix(':').map(|p| p.parse()).transpose()
            .map_err(|_| ioerr("bad port in URL"))?;
        (r[..end].to_string(), port.unwrap_or(default))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| ioerr("bad port in URL"))?),
            None => (authority.to_string(), default),
        }
    };
    if host.is_empty() {
        return Err(ioerr("URL has no host"));
    }
    Ok(Url { tls, host, port, path: path.to_string() })
}

fn strip_prefix_ci<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    (s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)).then(|| &s[p.len()..])
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<native_tls::TlsStream<TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(b),
            Conn::Tls(s) => s.read(b),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(b),
            Conn::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

fn connect(u: &Url) -> std::io::Result<BufReader<Conn>> {
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(u.host.as_str(), u.port))?
        .next()
        .ok_or_else(|| ioerr(&format!("cannot resolve {}", u.host)))?;
    let tcp = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_nodelay(true).ok();
    let conn = if u.tls {
        // Certificates are checked: unlike a BMC's self-signed web UI, this is
        // the image a server is about to boot, and it comes from wherever the
        // URL points.
        let c = native_tls::TlsConnector::new().map_err(|e| ioerr(&e.to_string()))?;
        Conn::Tls(Box::new(c.connect(&u.host, tcp).map_err(|e| ioerr(&format!("TLS: {e}")))?))
    } else {
        Conn::Plain(tcp)
    };
    Ok(BufReader::with_capacity(64 * 1024, conn))
}

/// One response's status line and the headers we act on.
struct Head {
    status: u16,
    length: Option<u64>,
    /// `Content-Range: bytes a-b/total`.
    range: Option<(u64, u64, Option<u64>)>,
    location: Option<String>,
    chunked: bool,
    close: bool,
}

fn read_head(r: &mut BufReader<Conn>) -> std::io::Result<Head> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed"));
    }
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("");
    let status = parts.next().and_then(|c| c.parse().ok()).ok_or_else(|| ioerr("not an HTTP response"))?;
    let mut h = Head {
        status,
        length: None,
        range: None,
        location: None,
        chunked: false,
        close: version == "HTTP/1.0",
    };
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Err(ioerr("connection closed in the response headers"));
        }
        let l = line.trim_end();
        if l.is_empty() {
            return Ok(h);
        }
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => h.length = v.parse().ok(),
            "location" => h.location = Some(v.to_string()),
            "transfer-encoding" => h.chunked = v.to_ascii_lowercase().contains("chunked"),
            "connection" => h.close = v.eq_ignore_ascii_case("close"),
            "content-range" => h.range = parse_content_range(v),
            _ => {}
        }
    }
}

fn parse_content_range(v: &str) -> Option<(u64, u64, Option<u64>)> {
    let v = v.strip_prefix("bytes")?.trim();
    let (span, total) = v.split_once('/')?;
    let (a, b) = span.split_once('-')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?, total.trim().parse().ok()))
}

/// Read and discard a body we do not want, so the connection can be reused.
fn skip_body(r: &mut BufReader<Conn>, h: &Head) -> std::io::Result<()> {
    if h.chunked {
        read_chunked(r, u64::MAX).map(|_| ())
    } else if let Some(n) = h.length {
        std::io::copy(&mut r.take(n), &mut std::io::sink()).map(|_| ())
    } else {
        Ok(())
    }
}

fn read_chunked(r: &mut BufReader<Conn>, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        r.read_line(&mut line)?;
        let n = u64::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| ioerr("bad chunk size"))?;
        if n == 0 {
            // Trailers, then the blank line.
            loop {
                line.clear();
                if r.read_line(&mut line)? == 0 || line.trim().is_empty() {
                    return Ok(out);
                }
            }
        }
        let mut chunk = vec![0u8; n as usize];
        r.read_exact(&mut chunk)?;
        if (out.len() as u64) < limit {
            out.extend_from_slice(&chunk);
        }
        line.clear();
        r.read_line(&mut line)?;
    }
}

pub struct Http {
    url: Url,
    size: u64,
    pos: u64,
    conn: Option<BufReader<Conn>>,
    /// The read-ahead window: its start offset and bytes.
    cache: (u64, Vec<u8>),
}

impl Http {
    /// Resolve redirects and learn the size with a one-byte ranged GET, which
    /// also proves the server honours ranges — without them every read would
    /// be the whole image.
    fn open(spec: &str) -> std::io::Result<Http> {
        let mut url = parse_url(spec)?;
        for _ in 0..=MAX_REDIRECTS {
            let mut conn = connect(&url)?;
            send_get(&mut conn, &url, 0, 0)?;
            let h = read_head(&mut conn)?;
            match h.status {
                301 | 302 | 303 | 307 | 308 => {
                    let loc = h.location.ok_or_else(|| ioerr("redirect without a Location"))?;
                    url = if is_url(&loc) {
                        parse_url(&loc)?
                    } else if loc.starts_with('/') {
                        Url { path: loc, ..url }
                    } else {
                        return Err(ioerr("unsupported relative redirect"));
                    };
                    continue;
                }
                206 => {
                    let size = h.range.and_then(|r| r.2)
                        .ok_or_else(|| ioerr("server did not report the image size"))?;
                    let keep = !h.close;
                    skip_body(&mut conn, &h)?;
                    return Ok(Http {
                        url,
                        size,
                        pos: 0,
                        conn: keep.then_some(conn),
                        cache: (0, Vec::new()),
                    });
                }
                200 => return Err(ioerr(
                    "the server ignores Range requests, so the image cannot be read in pieces")),
                404 => return Err(ioerr("image not found (HTTP 404)")),
                416 => return Err(ioerr("the image is empty")),
                s => return Err(ioerr(&format!("HTTP {s} fetching the image"))),
            }
        }
        Err(ioerr("too many redirects"))
    }

    fn fetch(&mut self, start: u64, end: u64) -> std::io::Result<Vec<u8>> {
        // A kept-alive connection the server has since closed fails on first
        // use; one retry on a fresh connection covers that.
        for attempt in 0..2 {
            let mut conn = match self.conn.take() {
                Some(c) => c,
                None => connect(&self.url)?,
            };
            match fetch_on(&mut conn, &self.url, start, end) {
                Ok((data, keep)) => {
                    if keep {
                        self.conn = Some(conn);
                    }
                    return Ok(data);
                }
                Err(e) if attempt == 0 && e.kind() != std::io::ErrorKind::InvalidData => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let (cstart, ref data) = self.cache;
        let in_cache = self.pos >= cstart && self.pos < cstart + data.len() as u64;
        if !in_cache {
            let end = (self.pos + WINDOW.max(buf.len() as u64)).min(self.size) - 1;
            let data = self.fetch(self.pos, end)?;
            self.cache = (self.pos, data);
        }
        let (cstart, ref data) = self.cache;
        let off = (self.pos - cstart) as usize;
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }

    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let p = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(ioerr("seek before the start of the image"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

fn send_get(conn: &mut BufReader<Conn>, u: &Url, start: u64, end: u64) -> std::io::Result<()> {
    let host = if (u.tls && u.port == 443) || (!u.tls && u.port == 80) {
        u.host.clone()
    } else {
        format!("{}:{}", u.host, u.port)
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nRange: bytes={start}-{end}\r\n\
         User-Agent: bmc-kvm\r\nAccept-Encoding: identity\r\n\r\n",
        u.path
    );
    conn.get_mut().write_all(req.as_bytes())?;
    conn.get_mut().flush()
}

/// One ranged GET on an open connection. Returns the bytes and whether the
/// connection may be reused.
fn fetch_on(conn: &mut BufReader<Conn>, u: &Url, start: u64, end: u64)
    -> std::io::Result<(Vec<u8>, bool)>
{
    send_get(conn, u, start, end)?;
    let h = read_head(conn)?;
    if h.status != 206 {
        // InvalidData marks a real answer, so `fetch` does not retry it.
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            format!("HTTP {} reading bytes {start}-{end} of the image", h.status)));
    }
    if h.range.is_some_and(|(a, _, _)| a != start) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "the server answered a different range than was asked for"));
    }
    let want = end - start + 1;
    let data = if h.chunked {
        read_chunked(conn, want)?
    } else {
        let n = h.length.unwrap_or(want);
        let mut d = vec![0u8; n as usize];
        conn.read_exact(&mut d)?;
        d
    };
    if data.is_empty() {
        return Err(ioerr("the server returned no data"));
    }
    Ok((data, !h.close))
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
