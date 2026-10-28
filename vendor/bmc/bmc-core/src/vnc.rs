//! Standard RFB (VNC) protocol — framebuffer decoding and input encoding.
//!
//! Distinct from `rfb.rs`, which speaks ATEN's InsydeVNC dialect (security type
//! 16, AST2100 rectangles). This is plain RFB 3.8 as specified, used by Dell
//! iDRAC 9, whose console is a lightly-extended noVNC server ("OpenVNC") reached
//! over a WebSocket.
//!
//! Encodings implemented: Raw, CopyRect, RRE, Hextile, plus the DesktopSize
//! pseudo-encoding. Tight and ZRLE are deliberately not advertised — a
//! conformant server may only use encodings the client asked for.

use crate::ast2100;

pub const ENC_RAW: i32 = 0;
pub const ENC_COPYRECT: i32 = 1;
pub const ENC_RRE: i32 = 2;
pub const ENC_HEXTILE: i32 = 5;
pub const ENC_DESKTOP_SIZE: i32 = -223;

/// The encodings we can actually decode, in server-preference order.
pub const SUPPORTED: [i32; 5] = [ENC_HEXTILE, ENC_RRE, ENC_COPYRECT, ENC_RAW, ENC_DESKTOP_SIZE];

/// RFB pixel layout, as announced in ServerInit (or set by SetPixelFormat).
#[derive(Clone, Copy, Debug)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    pub fn parse(b: &[u8]) -> Option<PixelFormat> {
        if b.len() < 16 {
            return None;
        }
        Some(PixelFormat {
            bits_per_pixel: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            red_max: u16::from_be_bytes([b[4], b[5]]),
            green_max: u16::from_be_bytes([b[6], b[7]]),
            blue_max: u16::from_be_bytes([b[8], b[9]]),
            red_shift: b[10],
            green_shift: b[11],
            blue_shift: b[12],
        })
    }

    pub fn bytes_per_pixel(&self) -> usize {
        (self.bits_per_pixel as usize).div_ceil(8)
    }

    /// Read one pixel and convert it to 0xRRGGBB.
    fn pixel(&self, b: &[u8]) -> u32 {
        let bpp = self.bytes_per_pixel();
        let raw: u32 = match bpp {
            1 => b[0] as u32,
            2 => {
                if self.big_endian {
                    u16::from_be_bytes([b[0], b[1]]) as u32
                } else {
                    u16::from_le_bytes([b[0], b[1]]) as u32
                }
            }
            _ => {
                if self.big_endian {
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
                } else {
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                }
            }
        };
        let r = (raw >> self.red_shift) & self.red_max as u32;
        let g = (raw >> self.green_shift) & self.green_max as u32;
        let b_ = (raw >> self.blue_shift) & self.blue_max as u32;
        (scale(r, self.red_max) << 16) | (scale(g, self.green_max) << 8) | scale(b_, self.blue_max)
    }
}

/// Widen a channel of `max` range to 8 bits.
fn scale(v: u32, max: u16) -> u32 {
    if max == 0 {
        return 0;
    }
    (v * 255 + max as u32 / 2) / max as u32
}

/// Incremental RFB message decoder.
///
/// RFB is a byte stream with variably sized messages, and the transport hands it
/// to us in arbitrary chunks, so `feed` decodes only whole messages and keeps the
/// remainder. Every decoder path is written to fail rather than panic on a short
/// or malformed rectangle — the data is remote input.
pub struct Decoder {
    pub format: PixelFormat,
    buf: Vec<u8>,
    /// Set when the server resized the desktop; the caller re-requests a frame.
    pub resized: bool,
    /// Tolerate Dell's private server messages (RFB type 247). iDRAC normally
    /// delivers them in their own WebSocket frames, where the transport filters
    /// them out, but nothing in RFB guarantees that framing.
    pub dell_extensions: bool,
}

impl Decoder {
    /// `dell_extensions` accepts Dell's private server messages inline; plain
    /// RFB servers never send them, so leave it off for anything but iDRAC.
    pub fn new(format: PixelFormat, dell_extensions: bool) -> Self {
        Decoder { format, buf: Vec::new(), resized: false, dell_extensions }
    }

    /// Feed transport bytes. Returns the number of framebuffer updates completed.
    pub fn feed(&mut self, data: &[u8], fb: &mut ast2100::Decoder) -> std::io::Result<u32> {
        self.buf.extend_from_slice(data);
        fb.bytes_in += data.len() as u64;
        let mut updates = 0;
        loop {
            match self.step(fb)? {
                Step::Incomplete => return Ok(updates),
                Step::Update => {
                    updates += 1;
                    fb.frames += 1;
                }
                Step::Other => {}
            }
        }
    }

    fn step(&mut self, fb: &mut ast2100::Decoder) -> std::io::Result<Step> {
        let Some(&ty) = self.buf.first() else { return Ok(Step::Incomplete) };
        match ty {
            0 => self.framebuffer_update(fb),
            1 => {
                // SetColourMapEntries: [1][pad][first:u16][count:u16] + 6*count
                if self.buf.len() < 6 {
                    return Ok(Step::Incomplete);
                }
                let n = u16::from_be_bytes([self.buf[4], self.buf[5]]) as usize;
                let total = 6 + n * 6;
                if self.buf.len() < total {
                    return Ok(Step::Incomplete);
                }
                self.buf.drain(..total);
                Ok(Step::Other)
            }
            2 => {
                self.buf.drain(..1); // Bell
                Ok(Step::Other)
            }
            3 => {
                // ServerCutText: [3][pad;3][len:u32] + text
                if self.buf.len() < 8 {
                    return Ok(Step::Incomplete);
                }
                let n = u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]) as usize;
                if self.buf.len() < 8 + n {
                    return Ok(Step::Incomplete);
                }
                self.buf.drain(..8 + n);
                Ok(Step::Other)
            }
            247 if self.dell_extensions => self.dell_message(),
            other => Err(ioerr(&format!("unknown RFB server message type {other}"))),
        }
    }

    /// Skip one Dell extension message. Only the fixed-size subtypes can be
    /// stepped over safely; the variable-length client list (172) appears during
    /// the handshake, where the transport handles it.
    fn dell_message(&mut self) -> std::io::Result<Step> {
        let Some(&sub) = self.buf.get(1) else { return Ok(Step::Incomplete) };
        let payload = match sub {
            179 => 0,              // "send key2"
            168 | 169 | 178 => 1,  // lockdown status / shutdown reason / keyboard LEDs
            171 => 2,              // frames per second
            170 => 6,              // stats: frame rate, compression, packet rate
            other => {
                return Err(ioerr(&format!(
                    "Dell RFB extension {other} cannot be skipped inline"
                )))
            }
        };
        if self.buf.len() < 2 + payload {
            return Ok(Step::Incomplete);
        }
        self.buf.drain(..2 + payload);
        Ok(Step::Other)
    }

    fn framebuffer_update(&mut self, fb: &mut ast2100::Decoder) -> std::io::Result<Step> {
        if self.buf.len() < 4 {
            return Ok(Step::Incomplete);
        }
        let rects = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
        // Rectangles are variable length, so measure the whole update before
        // consuming anything: a partial update must leave the buffer untouched.
        let mut off = 4;
        for _ in 0..rects {
            match self.rect_len(off)? {
                Some(n) => off += n,
                None => return Ok(Step::Incomplete),
            }
        }
        let mut cur = 4;
        for _ in 0..rects {
            let n = self.rect_len(cur)?.expect("measured above");
            self.draw_rect(cur, fb)?;
            cur += n;
        }
        self.buf.drain(..off);
        Ok(Step::Update)
    }

    /// Total byte length of the rectangle at `off`, or None if not all here yet.
    fn rect_len(&self, off: usize) -> std::io::Result<Option<usize>> {
        let b = &self.buf;
        if b.len() < off + 12 {
            return Ok(None);
        }
        let w = u16::from_be_bytes([b[off + 4], b[off + 5]]) as usize;
        let h = u16::from_be_bytes([b[off + 6], b[off + 7]]) as usize;
        let enc = i32::from_be_bytes([b[off + 8], b[off + 9], b[off + 10], b[off + 11]]);
        let bpp = self.format.bytes_per_pixel();
        let body = match enc {
            ENC_RAW => w * h * bpp,
            ENC_COPYRECT => 4,
            ENC_RRE => {
                if b.len() < off + 12 + 4 + bpp {
                    return Ok(None);
                }
                let n = u32::from_be_bytes([b[off + 12], b[off + 13], b[off + 14], b[off + 15]]) as usize;
                4 + bpp + n * (bpp + 8)
            }
            ENC_HEXTILE => match self.hextile_len(off + 12, w, h)? {
                Some(n) => n,
                None => return Ok(None),
            },
            ENC_DESKTOP_SIZE => 0,
            other => return Err(ioerr(&format!("unsupported RFB encoding {other}"))),
        };
        Ok(Some(12 + body))
    }

    /// Hextile is self-describing per tile, so its length can only be found by
    /// walking the tiles.
    fn hextile_len(&self, mut off: usize, w: usize, h: usize) -> std::io::Result<Option<usize>> {
        let b = &self.buf;
        let bpp = self.format.bytes_per_pixel();
        let start = off;
        let mut y = 0;
        while y < h {
            let th = (h - y).min(16);
            let mut x = 0;
            while x < w {
                let tw = (w - x).min(16);
                if b.len() < off + 1 {
                    return Ok(None);
                }
                let mask = b[off];
                off += 1;
                if mask & 0x01 != 0 {
                    // Raw tile
                    off += tw * th * bpp;
                } else {
                    if mask & 0x02 != 0 {
                        off += bpp; // background
                    }
                    if mask & 0x04 != 0 {
                        off += bpp; // foreground
                    }
                    if mask & 0x08 != 0 {
                        if b.len() < off + 1 {
                            return Ok(None);
                        }
                        let n = b[off] as usize;
                        off += 1;
                        // Each subrect: optional colour + 2 bytes of geometry.
                        off += n * (if mask & 0x10 != 0 { bpp + 2 } else { 2 });
                    }
                }
                if b.len() < off {
                    return Ok(None);
                }
                x += tw;
            }
            y += th;
        }
        Ok(Some(off - start))
    }

    fn draw_rect(&mut self, off: usize, fb: &mut ast2100::Decoder) -> std::io::Result<()> {
        let b = &self.buf;
        let x = u16::from_be_bytes([b[off], b[off + 1]]) as usize;
        let y = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
        let w = u16::from_be_bytes([b[off + 4], b[off + 5]]) as usize;
        let h = u16::from_be_bytes([b[off + 6], b[off + 7]]) as usize;
        let enc = i32::from_be_bytes([b[off + 8], b[off + 9], b[off + 10], b[off + 11]]);
        let body = off + 12;
        let bpp = self.format.bytes_per_pixel();

        match enc {
            ENC_DESKTOP_SIZE => {
                if w > 0 && h > 0 && w <= 4096 && h <= 4096 && (fb.width != w || fb.height != h) {
                    fb.resize(w, h);
                }
                self.resized = true;
            }
            ENC_RAW => {
                fb.mark(x, y, w, h);
                for row in 0..h {
                    for col in 0..w {
                        let p = self.format.pixel(&b[body + (row * w + col) * bpp..]);
                        put(fb, x + col, y + row, p);
                    }
                }
            }
            ENC_COPYRECT => {
                let sx = u16::from_be_bytes([b[body], b[body + 1]]) as usize;
                let sy = u16::from_be_bytes([b[body + 2], b[body + 3]]) as usize;
                copy_rect(fb, sx, sy, x, y, w, h);
            }
            ENC_RRE => {
                let n = u32::from_be_bytes([b[body], b[body + 1], b[body + 2], b[body + 3]]) as usize;
                let bg = self.format.pixel(&b[body + 4..]);
                fill(fb, x, y, w, h, bg);
                let mut o = body + 4 + bpp;
                for _ in 0..n {
                    let c = self.format.pixel(&b[o..]);
                    let sx = u16::from_be_bytes([b[o + bpp], b[o + bpp + 1]]) as usize;
                    let sy = u16::from_be_bytes([b[o + bpp + 2], b[o + bpp + 3]]) as usize;
                    let sw = u16::from_be_bytes([b[o + bpp + 4], b[o + bpp + 5]]) as usize;
                    let sh = u16::from_be_bytes([b[o + bpp + 6], b[o + bpp + 7]]) as usize;
                    fill(fb, x + sx, y + sy, sw, sh, c);
                    o += bpp + 8;
                }
            }
            ENC_HEXTILE => self.draw_hextile(body, x, y, w, h, fb),
            other => return Err(ioerr(&format!("unsupported RFB encoding {other}"))),
        }
        Ok(())
    }

    fn draw_hextile(&self, mut off: usize, rx: usize, ry: usize, w: usize, h: usize,
                    fb: &mut ast2100::Decoder) {
        let b = &self.buf;
        let bpp = self.format.bytes_per_pixel();
        // Background and foreground persist across tiles unless a tile resends them.
        let (mut bg, mut fg) = (0u32, 0u32);
        let mut y = 0;
        while y < h {
            let th = (h - y).min(16);
            let mut x = 0;
            while x < w {
                let tw = (w - x).min(16);
                let mask = b[off];
                off += 1;
                if mask & 0x01 != 0 {
                    fb.mark(rx + x, ry + y, tw, th);
                    for r in 0..th {
                        for c in 0..tw {
                            let p = self.format.pixel(&b[off + (r * tw + c) * bpp..]);
                            put(fb, rx + x + c, ry + y + r, p);
                        }
                    }
                    off += tw * th * bpp;
                } else {
                    if mask & 0x02 != 0 {
                        bg = self.format.pixel(&b[off..]);
                        off += bpp;
                    }
                    if mask & 0x04 != 0 {
                        fg = self.format.pixel(&b[off..]);
                        off += bpp;
                    }
                    fill(fb, rx + x, ry + y, tw, th, bg);
                    if mask & 0x08 != 0 {
                        let n = b[off] as usize;
                        off += 1;
                        let coloured = mask & 0x10 != 0;
                        for _ in 0..n {
                            let c = if coloured {
                                let c = self.format.pixel(&b[off..]);
                                off += bpp;
                                c
                            } else {
                                fg
                            };
                            // Packed geometry: x|y in one byte, w-1|h-1 in the next.
                            let xy = b[off];
                            let wh = b[off + 1];
                            off += 2;
                            let (sx, sy) = ((xy >> 4) as usize, (xy & 0x0F) as usize);
                            let (sw, sh) = ((wh >> 4) as usize + 1, (wh & 0x0F) as usize + 1);
                            fill(fb, rx + x + sx, ry + y + sy, sw, sh, c);
                        }
                    }
                }
                x += tw;
            }
            y += th;
        }
    }
}

enum Step {
    Incomplete,
    Update,
    Other,
}

/// Writes one pixel. It does not mark damage — that would cost a tile lookup
/// per pixel — so its callers mark the rectangle they fill with it.
fn put(fb: &mut ast2100::Decoder, x: usize, y: usize, px: u32) {
    if x < fb.width && y < fb.height {
        let w = fb.width;
        fb.framebuffer[y * w + x] = px;
    }
}

fn fill(fb: &mut ast2100::Decoder, x: usize, y: usize, w: usize, h: usize, px: u32) {
    fb.mark(x, y, w, h);
    let fw = fb.width;
    for r in y..(y + h).min(fb.height) {
        let lo = r * fw + x.min(fw);
        let hi = r * fw + (x + w).min(fw);
        if lo < hi {
            fb.framebuffer[lo..hi].fill(px);
        }
    }
}

/// CopyRect may overlap, so copy the source out before writing it back.
fn copy_rect(fb: &mut ast2100::Decoder, sx: usize, sy: usize, dx: usize, dy: usize,
             w: usize, h: usize) {
    let fw = fb.width;
    let mut tmp = vec![0u32; w * h];
    for r in 0..h {
        for c in 0..w {
            let (px, py) = (sx + c, sy + r);
            if px < fb.width && py < fb.height {
                tmp[r * w + c] = fb.framebuffer[py * fw + px];
            }
        }
    }
    fb.mark(dx, dy, w, h);
    for r in 0..h {
        for c in 0..w {
            put(fb, dx + c, dy + r, tmp[r * w + c]);
        }
    }
}

// ---------- client -> server messages ----------

/// SetEncodings with the encodings this decoder actually implements.
pub fn set_encodings(encodings: &[i32]) -> Vec<u8> {
    let mut m = vec![2u8, 0];
    m.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

/// How often to spend a frame measuring the round trip instead of fetching one.
pub const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// A one-pixel *non-incremental* request, used to time the console round trip.
///
/// An incremental request cannot measure latency: the server is entitled to sit
/// on it until the screen changes, so timing it measures idleness. A
/// non-incremental request must be answered straight away, and one pixel makes
/// the answer too small to matter.
///
/// RFB has no request ids, so the only way to know which request an update
/// answers is to have exactly one outstanding. Callers therefore send this
/// *instead of* the usual incremental request, not alongside it, and resume
/// normal fetching once the answer arrives. The cost is one frame per sample.
pub fn ping() -> Vec<u8> {
    framebuffer_update_request(false, 0, 0, 1, 1)
}

pub fn framebuffer_update_request(incremental: bool, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
    let mut m = vec![3u8, incremental as u8];
    m.extend_from_slice(&x.to_be_bytes());
    m.extend_from_slice(&y.to_be_bytes());
    m.extend_from_slice(&w.to_be_bytes());
    m.extend_from_slice(&h.to_be_bytes());
    m
}

/// KeyEvent. `key` is an X11 keysym — exactly what the GUI's `gui_keys::keysym_for` produces.
pub fn key_event(key: u32, down: bool) -> Vec<u8> {
    let mut m = vec![4u8, down as u8, 0, 0];
    m.extend_from_slice(&key.to_be_bytes());
    m
}

/// PointerEvent. Buttons are bit 0 left, 1 middle, 2 right, 3/4 wheel up/down.
pub fn pointer_event(x: u16, y: u16, buttons: u8) -> Vec<u8> {
    let mut m = vec![5u8, buttons];
    m.extend_from_slice(&x.to_be_bytes());
    m.extend_from_slice(&y.to_be_bytes());
    m
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}

/// The client-texture replay over streams built from RFC 6143 (§7.6.1 and
/// §7.7): after every update, a client that paints only the damage must hold
/// exactly the decoder's picture.
#[cfg(test)]
mod damage_replay {
    use super::*;
    use crate::damage::tests::Replay;

    /// 32 bits per pixel, little-endian, 8 bits a channel: bytes B, G, R, X.
    const FORMAT: PixelFormat = PixelFormat {
        bits_per_pixel: 32, depth: 24, big_endian: false, true_colour: true,
        red_max: 255, green_max: 255, blue_max: 255, red_shift: 16, green_shift: 8, blue_shift: 0,
    };

    fn px(c: u32) -> [u8; 4] {
        c.to_le_bytes()
    }

    fn rect(x: u16, y: u16, w: u16, h: u16, enc: i32, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        for v in [x, y, w, h] {
            r.extend_from_slice(&v.to_be_bytes());
        }
        r.extend_from_slice(&enc.to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    fn update(rects: &[Vec<u8>]) -> Vec<u8> {
        let mut m = vec![0u8, 0];
        m.extend_from_slice(&(rects.len() as u16).to_be_bytes());
        rects.iter().for_each(|r| m.extend_from_slice(r));
        m
    }

    fn raw(w: usize, h: usize, seed: u32) -> Vec<u8> {
        (0..w * h).flat_map(|i| px((i as u32).wrapping_mul(2_654_435_761).wrapping_add(seed) & 0xFF_FFFF)).collect()
    }

    #[test]
    fn every_encoding_marks_what_it_draws() {
        let mut fb = ast2100::Decoder::new(120, 90);
        let mut dec = Decoder::new(FORMAT, false);
        let mut rp = Replay::default();
        rp.step(&mut fb, "new");

        // Raw.
        assert_eq!(dec.feed(&update(&[rect(5, 5, 40, 30, ENC_RAW, &raw(40, 30, 1))]), &mut fb).unwrap(), 1);
        assert!(!rp.step(&mut fb, "raw").unwrap().full);

        // CopyRect onto an area overlapping its own source.
        let src = [0u8, 5, 0, 5];
        dec.feed(&update(&[rect(20, 12, 40, 30, ENC_COPYRECT, &src)]), &mut fb).unwrap();
        rp.step(&mut fb, "copyrect");

        // RRE: a background and two sub-rectangles.
        let mut rre = 2u32.to_be_bytes().to_vec();
        rre.extend_from_slice(&px(0x112233));
        for (c, sx, sy, sw, sh) in [(0xAA0000u32, 2u16, 3u16, 10u16, 5u16), (0x00BB00, 30, 10, 15, 8)] {
            rre.extend_from_slice(&px(c));
            for v in [sx, sy, sw, sh] {
                rre.extend_from_slice(&v.to_be_bytes());
            }
        }
        dec.feed(&update(&[rect(60, 40, 50, 20, ENC_RRE, &rre)]), &mut fb).unwrap();
        rp.step(&mut fb, "rre");

        // Hextile, 40x20: tiles of 16x16, 16x16, 8x16, then 16x4, 16x4, 8x4.
        let mut hx = Vec::new();
        hx.push(0x0E); // background, foreground, one plain sub-rectangle
        hx.extend_from_slice(&px(0x0000CC));
        hx.extend_from_slice(&px(0xEEEEEE));
        hx.extend_from_slice(&[1, 0x23, 0x45]);
        hx.push(0x01); // raw
        hx.extend_from_slice(&raw(16, 16, 7));
        hx.push(0x00); // the background carried over
        hx.push(0x18); // two coloured sub-rectangles
        hx.push(2);
        hx.extend_from_slice(&px(0x445566));
        hx.extend_from_slice(&[0x00, 0x31]);
        hx.extend_from_slice(&px(0x778899));
        hx.extend_from_slice(&[0x52, 0x00]);
        hx.push(0x02); // a new background
        hx.extend_from_slice(&px(0x101010));
        hx.push(0x01); // raw, the 8x4 corner
        hx.extend_from_slice(&raw(8, 4, 9));
        dec.feed(&update(&[rect(0, 50, 40, 20, ENC_HEXTILE, &hx)]), &mut fb).unwrap();
        assert!(!rp.step(&mut fb, "hextile").unwrap().full);

        // An update with nothing in it is no damage.
        dec.feed(&update(&[]), &mut fb).unwrap();
        assert_eq!(rp.step(&mut fb, "static"), None);

        // DesktopSize, then a raw rectangle on the new screen.
        dec.feed(&update(&[rect(0, 0, 100, 70, ENC_DESKTOP_SIZE, &[])]), &mut fb).unwrap();
        assert!(rp.step(&mut fb, "desktop size").unwrap().resized);
        dec.feed(&update(&[rect(90, 60, 10, 10, ENC_RAW, &raw(10, 10, 3))]), &mut fb).unwrap();
        rp.step(&mut fb, "raw after resize");
        assert!(rp.partial >= 5);
    }
}
