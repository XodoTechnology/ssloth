//! A single-file HTTP server, used to hand ISOs to iLO virtual media.
//!
//! iLO does not accept a pushed SCSI stream the way the ATEN and AMI BMCs do.
//! Its virtual media takes a URL and the BMC fetches the image itself, with
//! ranged GETs, for as long as the media stays inserted. So mounting a local ISO
//! means serving it from this machine on an address the BMC can reach, and
//! keeping that server up until the media is ejected.
//!
//! Only what iLO asks for: GET and HEAD, one file, `Range: bytes=a-b`.

use crate::vmedia::{Mount, Stats};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Serve `path` over HTTP until the returned `Mount` is dropped/unmounted.
/// Returns the mount plus the URL to hand the BMC.
pub fn serve(path: &str, bmc_host: &str) -> std::io::Result<(Mount, String)> {
    let file = std::path::Path::new(path);
    let size = std::fs::metadata(file)?.len();
    let name = file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image.iso".into());

    // Bind on every interface so the BMC can reach us whichever way it routes.
    let listener = TcpListener::bind(("0.0.0.0", 0))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;

    // The address the BMC will see us on, chosen by the routing table.
    let local = local_ip_for(bmc_host)
        .ok_or_else(|| ioerr("cannot determine a local address reachable from the BMC"))?;

    // An unguessable path segment: the listener is open to the whole network.
    let token = token();
    let url_path = format!("/vm/{token}/{}", url_encode(&name));
    let url = format!("http://{local}:{port}{url_path}");

    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());
    let (s, st, p) = (stop.clone(), stats.clone(), path.to_string());
    let handle = std::thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((sock, _)) => {
                    let (st, p, want, s2) = (st.clone(), p.clone(), url_path.clone(), s.clone());
                    std::thread::spawn(move || {
                        let _ = handle_conn(sock, &p, &want, &st, &s2);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(80));
                }
                Err(_) => break,
            }
        }
    });

    Ok((Mount::from_parts(stop, handle, path.to_string(), size, stats), url))
}

fn handle_conn(
    sock: TcpStream,
    path: &str,
    want_path: &str,
    stats: &Arc<Stats>,
    stop: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    sock.set_read_timeout(Some(Duration::from_secs(30)))?;
    sock.set_nodelay(true).ok();
    let mut w = sock.try_clone()?;
    let mut r = BufReader::new(sock);
    let mut f = std::fs::File::open(path)?;
    let size = f.metadata()?.len();

    // iLO reuses a connection for many ranged reads; serve until it goes away.
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();

        let mut range: Option<(u64, u64)> = None;
        loop {
            let mut h = String::new();
            if r.read_line(&mut h)? == 0 {
                return Ok(());
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some(v) = h.to_ascii_lowercase().strip_prefix("range:") {
                range = parse_range(v.trim(), size);
            }
        }

        stats.commands.fetch_add(1, Ordering::Relaxed);

        if target != want_path {
            write_head(&mut w, 404, "Not Found", 0, None, size)?;
            return Ok(());
        }
        if method != "GET" && method != "HEAD" {
            write_head(&mut w, 405, "Method Not Allowed", 0, None, size)?;
            return Ok(());
        }

        let (start, end) = range.unwrap_or((0, size.saturating_sub(1)));
        if size == 0 || start >= size {
            write_head(&mut w, 416, "Range Not Satisfiable", 0, None, size)?;
            return Ok(());
        }
        let len = end - start + 1;
        let (code, reason) = if range.is_some() { (206, "Partial Content") } else { (200, "OK") };
        write_head(&mut w, code, reason, len, range.map(|_| (start, end)), size)?;
        if method == "HEAD" {
            continue;
        }

        stats.reads.fetch_add(1, Ordering::Relaxed);
        f.seek(SeekFrom::Start(start))?;
        let mut left = len;
        let mut buf = vec![0u8; 256 * 1024];
        while left > 0 {
            if stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            let want = left.min(buf.len() as u64) as usize;
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n])?;
            stats.bytes.fetch_add(n as u64, Ordering::Relaxed);
            left -= n as u64;
        }
        w.flush()?;
    }
}

fn write_head(
    w: &mut TcpStream,
    code: u16,
    reason: &str,
    len: u64,
    range: Option<(u64, u64)>,
    total: u64,
) -> std::io::Result<()> {
    let mut h = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/octet-stream\r\n\
         Accept-Ranges: bytes\r\nContent-Length: {len}\r\n"
    );
    if let Some((s, e)) = range {
        h.push_str(&format!("Content-Range: bytes {s}-{e}/{total}\r\n"));
    }
    h.push_str("\r\n");
    w.write_all(h.as_bytes())
}

/// `bytes=a-b`, `bytes=a-`, or `bytes=-n` (suffix). Clamped to the file.
fn parse_range(v: &str, size: u64) -> Option<(u64, u64)> {
    let spec = v.strip_prefix("bytes=")?.split(',').next()?.trim();
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        let n: u64 = b.trim().parse().ok()?;
        (size.saturating_sub(n), size.saturating_sub(1))
    } else {
        let start: u64 = a.trim().parse().ok()?;
        let end = if b.trim().is_empty() {
            size.saturating_sub(1)
        } else {
            b.trim().parse::<u64>().ok()?.min(size.saturating_sub(1))
        };
        (start, end)
    };
    if start > end {
        return None;
    }
    Some((start, end))
}

/// Which of our addresses the BMC would see. Connecting a UDP socket sends no
/// packets but makes the kernel pick the source address for that route.
fn local_ip_for(host: &str) -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((host, 80)).ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
}

fn token() -> String {
    // This is the whole access control on a `mount-url` image, so it comes from
    // the OS rather than the clock. See `rand`.
    crate::rand::hex(12)
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
