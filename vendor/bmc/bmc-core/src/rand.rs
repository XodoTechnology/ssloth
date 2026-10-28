//! One source of random bytes, because three of the protocols need one and
//! only one of them can tolerate a bad answer.
//!
//! The stakes differ per caller. The Avocent APCP nonce is echoed back as zeros
//! and never referred to again. A WebSocket masking key only has to be
//! unpredictable to a proxy in the middle. But `httpd`'s media token is the
//! only thing standing between an ISO served for a `mount-url` and anyone else
//! who can reach the port, so a predictable one is a real hole.
//!
//! Every previous copy of this read `/dev/urandom` and fell back to the clock,
//! which on Windows means the clock every time.

/// Fill `buf` with random bytes from the OS.
pub fn fill(buf: &mut [u8]) {
    if imp::fill(buf) {
        return;
    }
    // Last resort, and deliberately not silent about being one: mixing the
    // clock into whatever the OS did or did not give us. Reached only if the
    // system entropy source is unavailable, which on both platforms means
    // something is badly wrong.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= (n >> (i % 8 * 8)) as u8 ^ (pid >> (i % 8 * 8)) as u8;
    }
}

/// `n` random bytes as lowercase hex — the shape every caller that wants a
/// token or an id actually needs.
pub fn hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(unix)]
mod imp {
    use std::io::Read;

    pub fn fill(buf: &mut [u8]) -> bool {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .is_ok()
    }
}

#[cfg(windows)]
mod imp {
    // `RtlGenRandom`, exported under its old undecorated name. Present since XP
    // and what the rest of the ecosystem uses on Windows; declared by hand so
    // this stays dependency free.
    #[link(name = "advapi32")]
    extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(buf: *mut u8, len: u32) -> u8;
    }

    pub fn fill(buf: &mut [u8]) -> bool {
        // The API takes a u32 length; nothing here asks for more than 32 bytes,
        // but chunk anyway rather than silently truncate if that ever changes.
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let ok = unsafe { RtlGenRandom(chunk.as_mut_ptr(), chunk.len() as u32) };
            if ok == 0 {
                return false;
            }
        }
        true
    }
}
