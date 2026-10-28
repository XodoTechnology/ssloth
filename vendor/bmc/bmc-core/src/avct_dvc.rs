//! Avocent "DVC" video decoder — the codec behind the Dell iDRAC 8 console.
//!
//! A port of the decoder iDRAC 8 serves to its own HTML5 viewer
//! (`js/ViewerJS/viewer/dvcdecoder.js` + `decompressdvc.js`, saved under
//! `~/.config/smc-ikvm/idrac8-ref/`). Not the same codec as HP's DVC in
//! `ilo_dvc.rs`, despite the name and the shared colour depths: this one is
//! byte-oriented, with no state table and no colour cache.
//!
//! Each frame is one command stream over the whole screen, left to right and
//! top to bottom, against a pixel store that survives from the previous frame:
//!
//! | top bits | command |
//! |---|---|
//! | `000` | skip n pixels — unchanged since the last frame |
//! | `001` | repeat the pixel to the left n times |
//! | `010` | copy n pixels from the row above |
//! | `011` | 2-colour bitmap: the pixel to the left and the nearest different one before it |
//! | `1xx` | a literal pixel, 1-3 bytes depending on the colour depth |
//!
//! A run's length continues across consecutive bytes with the same command, 5
//! bits at a time. The 23-bit "DVC23X" variant splits on four bits instead and
//! adds small per-channel deltas from the left, above or previous-frame pixel.
//!
//! The pixel store holds the codec's own pixel words — RGB555 at 15 bits, a
//! palette or grey level at 7, 8/8/7-bit RGB at 23 — because every command
//! compares and copies those, not display colours. They are converted into the
//! shared framebuffer only once a frame is complete.

use crate::ast2100;

/// Video message ids (the "secondary" — video-channel — numbering).
pub const DVC15: u16 = 0x0081;
pub const DVC7: u16 = 0x0082;
pub const DVC7_GREY: u16 = 0x0083;
pub const DVC23: u16 = 0x008A;
pub const DVC23X: u16 = 0x008F;

/// True for the message ids this decoder takes.
pub fn handles(id: u16) -> bool {
    matches!(id, DVC15 | DVC7 | DVC7_GREY | DVC23 | DVC23X)
}

// Fragment flags (the reference's AVSP_RLE_GRAPHICS_FLAGS_*).
const SOF: u8 = 0x01;
const EOF: u8 = 0x02;
/// A reference (key) frame: the only kind a stream may start on.
const REF: u8 = 0x04;
const SOB: u8 = 0x10;

/// The 7-bit colour palette: a 5x5x5 cube at these levels plus three greys,
/// reordered by the table below. Both straight from `dvc7ColorMap`.
const LEVELS: [u32; 5] = [0, 70, 127, 191, 255];
const DVC7_ORDER: [usize; 128] = [
    0, 25, 50, 75, 5, 30, 55, 80, 10, 35, 60, 85, 15, 40, 65, 90, 1, 26, 51, 76, 6, 31, 56, 81,
    11, 36, 61, 86, 16, 41, 66, 91, 2, 27, 52, 77, 7, 32, 57, 82, 12, 37, 62, 87, 17, 42, 67, 92,
    3, 28, 53, 78, 8, 33, 58, 83, 13, 38, 63, 88, 18, 43, 68, 93, 100, 101, 102, 103, 105, 106,
    107, 108, 110, 111, 112, 113, 115, 116, 117, 118, 20, 45, 70, 95, 21, 46, 71, 96, 22, 47, 72,
    97, 23, 48, 73, 98, 4, 29, 54, 79, 9, 34, 59, 84, 14, 39, 64, 89, 19, 44, 69, 94, 120, 121,
    122, 123, 104, 109, 114, 119, 24, 49, 74, 99, 124, 125, 126, 127,
];

fn dvc7_palette() -> [u32; 128] {
    let mut cube = [0u32; 128];
    for i in 0..125 {
        cube[i] = (LEVELS[i % 5] << 16) | (LEVELS[i / 5 % 5] << 8) | LEVELS[i / 25];
    }
    cube[125] = 0x5f5f5f;
    cube[126] = 0x9f9f9f;
    cube[127] = 0xdfdfdf;
    let mut out = [0u32; 128];
    for (o, &i) in out.iter_mut().zip(DVC7_ORDER.iter()) {
        *o = cube[i];
    }
    out
}

/// Extend a run length by one more continuation byte. A hostile stream can
/// repeat a command indefinitely; past the word size, or past any screen, the
/// length only needs to stay "too long", which the callers then refuse.
fn grow(len: usize, bits: usize, shift: u32) -> usize {
    if shift >= usize::BITS - 5 {
        return usize::MAX;
    }
    len.saturating_add(bits << shift) | len
}

#[derive(Clone, Copy)]
struct Scan {
    end: usize,
    c0: u32,
    hit: Option<usize>,
}

pub struct Dvc {
    width: usize,
    height: usize,
    /// 7, 15 or 23 — decides the literal size and the display conversion.
    depth: u8,
    /// False for the grey 7-bit stream, whose literals are levels, not indices.
    colour: bool,
    x23: bool,
    /// Pixel words carried from frame to frame; see the module comment.
    store: Vec<u32>,
    ptr: usize,
    msg: Vec<u8>,
    /// Nothing is decoded until a reference frame starts.
    started: bool,
    /// What the last `two_colours` scan proved, for the next to build on:
    /// every pixel in `(hit, end]` is `c0`, and `hit` (if any) is not.
    scan: Option<Scan>,
    /// Tests only: rescan from scratch every time, as the reference does.
    #[cfg(test)]
    naive: bool,
    palette: [u32; 128],
    /// The converted picture, reused frame to frame, which `blit` compares
    /// with the framebuffer to find the damage.
    scratch: Vec<u32>,
}

impl Default for Dvc {
    fn default() -> Self {
        Dvc {
            width: 0, height: 0, depth: 15, colour: true, x23: false,
            store: Vec::new(), ptr: 0, msg: Vec::new(), started: false,
            scan: None, palette: dvc7_palette(), scratch: Vec::new(),
            #[cfg(test)]
            naive: false,
        }
    }
}

impl Dvc {
    /// Feed one video message (payload after the 8-byte AVSP header). Returns
    /// true when it completed a frame, which is then in `fb`.
    pub fn push(&mut self, id: u16, p: &[u8], fb: &mut ast2100::Decoder) -> bool {
        if p.len() < 12 {
            return false;
        }
        let (depth, colour, x23) = match id {
            DVC7 => (7, true, false),
            DVC7_GREY => (7, false, false),
            DVC23 => (23, true, false),
            DVC23X => (23, true, true),
            _ => (15, true, false),
        };
        let height = u16::from_be_bytes([p[4], p[5]]) as usize;
        let width = u16::from_be_bytes([p[6], p[7]]) as usize;
        let flags = p[8];
        if width == 0 || height == 0 || width > 4096 || height > 4096 {
            return false;
        }
        if !self.started {
            // Joining mid-stream would decode skips and copies against a
            // store that never held the frame they refer to.
            if flags & (SOF | REF) != SOF | REF {
                return false;
            }
            self.started = true;
        }
        self.depth = depth;
        self.colour = colour;
        self.x23 = x23;
        if width != self.width || height != self.height {
            self.width = width;
            self.height = height;
            self.store = vec![0; width * height];
        }
        if flags & (SOB | SOF) != 0 {
            self.msg.clear();
            self.ptr = 0;
        }
        // The reference refuses a frame bigger than its raw size, which only a
        // corrupt stream can produce.
        let bpp = (depth as usize + 1) / 8;
        if self.msg.len() + p.len() - 12 > width * height * bpp {
            return false;
        }
        self.msg.extend_from_slice(&p[12..]);
        if flags & EOF == 0 {
            return false;
        }

        let data = std::mem::take(&mut self.msg);
        self.ptr = 0;
        self.scan = None;
        if self.x23 {
            self.decode23x(&data);
        } else {
            self.decode(&data, bpp);
        }
        self.blit(fb);
        true
    }

    fn at(&self, i: isize) -> u32 {
        if i < 0 { 0 } else { self.store.get(i as usize).copied().unwrap_or(0) }
    }

    fn put(&mut self, v: u32) {
        if let Some(s) = self.store.get_mut(self.ptr) {
            *s = v;
        }
        self.ptr += 1;
    }

    fn fill_left(&mut self, n: usize) {
        let v = self.at(self.ptr as isize - 1);
        for _ in 0..n {
            self.put(v);
        }
    }

    fn copy_above(&mut self, n: usize) {
        let src = self.ptr as isize - self.width as isize;
        for k in 0..n as isize {
            let v = self.at(src + k);
            self.put(v);
        }
    }

    /// A run command, once its length is known.
    fn run(&mut self, op: u8, n: usize) {
        match op {
            0x00 => self.ptr += n,
            0x20 => self.fill_left(n),
            _ => self.copy_above(n),
        }
    }

    /// The 2-colour bitmap's colours: the pixel to the left, and the nearest
    /// pixel before it that differs.
    ///
    /// The reference rescans from scratch every time, which a crafted frame of
    /// bitmaps over one colour turns into O(pixels²) under the framebuffer
    /// lock. Pixels behind the write pointer never change within a frame, so
    /// the previous scan's result stays true, and each scan only has to cover
    /// what was written since — the same answer, in linear time overall.
    fn two_colours(&mut self) -> (u32, u32) {
        #[cfg(test)]
        if self.naive {
            self.scan = None;
        }
        let c0 = self.at(self.ptr as isize - 1);
        let end = self.ptr.saturating_sub(1).min(self.store.len());
        let prev = self.scan.filter(|s| s.end <= end);
        // New pixels first: the nearest difference may be among them.
        let floor = prev.map_or(0, |s| s.end);
        if let Some(k) = (floor..end).rev().find(|&k| self.store[k] != c0) {
            return self.found(end, c0, Some(k));
        }
        // No difference among them, so the previous answer stands. Its `c0`
        // was the pixel at its own `end`, the first one re-read above, so it
        // is necessarily this `c0` too.
        debug_assert!(prev.map_or(true, |p| p.c0 == c0));
        let hit = prev.and_then(|p| p.hit);
        self.found(end, c0, hit)
    }

    fn found(&mut self, end: usize, c0: u32, hit: Option<usize>) -> (u32, u32) {
        self.scan = Some(Scan { end, c0, hit });
        (c0, hit.map_or(c0, |h| self.store[h]))
    }

    fn bits(&mut self, mut bits: u32, n: usize, c: (u32, u32)) {
        for _ in 0..n {
            self.put(if bits & 0x80 != 0 { c.1 } else { c.0 });
            bits <<= 1;
        }
    }

    /// The 7/15/23-bit stream (`uncompress_dvc4_data`).
    fn decode(&mut self, d: &[u8], bpp: usize) {
        let total = self.width * self.height;
        let byte = |i: usize| d.get(i).copied().unwrap_or(0) as u32;
        let (mut i, mut left) = (0usize, d.len() as isize);
        let mut count = 0usize;
        let (mut in_run, mut run_op, mut run_len, mut run_n) = (false, 0u8, 0usize, 0u32);
        while left > 0 {
            if count >= total {
                return;
            }
            let b = d[i];
            i += 1;
            left -= 1;
            let op = b & 0xE0;
            if in_run {
                if op == run_op {
                    run_n += 1;
                    run_len = grow(run_len, (b & 0x1F) as usize, run_n * 5);
                    continue;
                }
                // Faithful to the reference, which counts two extra pixels per
                // run at 7 bits in the middle of a stream but not at its end.
                if bpp == 1 {
                    run_len += 2;
                }
                if count.saturating_add(run_len) > total {
                    return;
                }
                self.run(run_op, run_len);
                count += run_len;
                in_run = false;
            }
            match op {
                0x00 | 0x20 | 0x40 => {
                    run_n = 0;
                    run_op = op;
                    run_len = (b & 0x1F) as usize;
                    in_run = true;
                }
                0x60 => {
                    let c = self.two_colours();
                    self.bits((b as u32) << 4, 4, c);
                    count += 4;
                    let mut more = b & 0x10 != 0;
                    while more {
                        if count + 7 > total {
                            break;
                        }
                        let b = byte(i);
                        i += 1;
                        if left > 0 {
                            left -= 1;
                        }
                        self.bits(b << 1, 7, c);
                        count += 7;
                        more = b & 0x80 != 0;
                    }
                }
                _ => {
                    let v = (b & 0x7F) as u32;
                    let px = match bpp {
                        1 if self.colour => self.palette[v as usize],
                        1 => { let g = v << 1; (g << 16) | (g << 8) | g }
                        2 => {
                            left -= 1;
                            i += 1;
                            (v << 8) | byte(i - 1)
                        }
                        _ => {
                            left -= 2;
                            i += 2;
                            (v << 16) | (byte(i - 2) << 8) | byte(i - 1)
                        }
                    };
                    self.put(px);
                    count += 1;
                }
            }
        }
        if in_run && count.saturating_add(run_len) <= total {
            self.run(run_op, run_len);
        }
    }

    /// Unpack a 23-bit word into 8-bit r, g, b. Blue has seven bits and its
    /// low bit copies its top one, as in the reference.
    fn rgb23(v: u32) -> (i32, i32, i32) {
        let r = ((v & 0x7F8000) >> 15) as i32;
        let g = ((v & 0x7F80) >> 7) as i32;
        let mut b = ((v & 0x7F) << 1) as i32;
        if b & 0x80 != 0 {
            b += 1;
        }
        (r, g, b)
    }

    /// A 4-bit sign-magnitude delta: 0-7 up, 8-15 down by 8 - (d & 7).
    fn delta(c: i32, d: u32) -> i32 {
        if d & 8 != 0 { c - (8 - (d & 7) as i32) } else { c + d as i32 }
    }

    /// The pixel at `src` nudged per channel, wrapping as the reference does.
    fn nudge(&mut self, src: isize, dr: u32, dg: u32, db: u32) {
        let (r, g, b) = Self::rgb23(self.at(src));
        let (r, g, b) = (Self::delta(r, dr), Self::delta(g, dg), Self::delta(b, db));
        self.put((((r & 0xFF) as u32) << 15) | (((g & 0xFF) as u32) << 7) | ((b & 0xFF) as u32 >> 1));
    }

    /// The DVC23X stream (`uncompress_dvc23X_data`): four-bit commands, with
    /// per-channel deltas in place of the 2-colour bitmap.
    fn decode23x(&mut self, d: &[u8]) {
        let total = self.width * self.height;
        let w = self.width as isize;
        let byte = |i: usize| d.get(i).copied().unwrap_or(0) as u32;
        let (mut i, mut left) = (0usize, d.len() as isize);
        let mut count = 0usize;
        let (mut in_run, mut run_op, mut run_len, mut run_n) = (false, 0u8, 0usize, 0u32);
        while left > 0 {
            if count >= total {
                return;
            }
            let b = d[i];
            i += 1;
            left -= 1;
            let op = b & 0xF0;
            if in_run {
                if op == run_op {
                    run_n += 1;
                    run_len = grow(run_len, (b & 0x0F) as usize, run_n * 4);
                    continue;
                }
                if count.saturating_add(run_len) > total {
                    return;
                }
                self.run(run_op, run_len);
                count += run_len;
                in_run = false;
            }
            let here = self.ptr as isize;
            let lo = (b & 0x0F) as u32;
            match op {
                0x00 | 0x20 | 0x40 => {
                    run_n = 0;
                    run_op = op;
                    run_len = lo as usize;
                    in_run = true;
                    continue;
                }
                0x10 | 0x30 | 0x50 => {
                    let n = byte(i);
                    i += 1;
                    left -= 1;
                    let src = match op { 0x10 => here, 0x30 => here - 1, _ => here - w };
                    self.nudge(src, lo, n >> 4, n & 0x0F);
                }
                0x60 => self.nudge(here - 1, lo, lo, lo),
                0x70 => self.nudge(here - w, lo, lo, lo),
                _ => {
                    i += 2;
                    left -= 2;
                    self.put((((b & 0x7F) as u32) << 16) | (byte(i - 2) << 8) | byte(i - 1));
                }
            }
            count += 1;
        }
        if in_run && count.saturating_add(run_len) <= total {
            self.run(run_op, run_len);
        }
    }

    /// Convert the pixel store into the shared framebuffer, marking the tiles
    /// that changed. The store is converted whole every frame anyway, so
    /// comparing while writing finds the damage exactly, with no bookkeeping
    /// in the run and copy operations that produced it.
    fn blit(&mut self, fb: &mut ast2100::Decoder) {
        if fb.width != self.width || fb.height != self.height {
            fb.resize(self.width, self.height);
        }
        self.scratch.resize(self.store.len(), 0);
        for (o, &v) in self.scratch.iter_mut().zip(self.store.iter()) {
            *o = match self.depth {
                7 => v & 0xFFFFFF,
                15 => (((v >> 10) & 0x1F) << 19) | (((v >> 5) & 0x1F) << 11) | ((v & 0x1F) << 3),
                _ => (((v >> 15) & 0xFF) << 16) | (((v >> 7) & 0xFF) << 8) | ((v & 0x7F) << 1),
            };
        }
        fb.write_diff(&self.scratch);
        fb.frames += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One fragment: the 12-byte sub-header, then the command stream.
    fn frag(w: u16, h: u16, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p[4..6].copy_from_slice(&h.to_be_bytes());
        p[6..8].copy_from_slice(&w.to_be_bytes());
        p[8] = flags;
        p.extend_from_slice(data);
        p
    }

    #[test]
    fn dvc15_commands() {
        let mut fb = ast2100::Decoder::new(4, 2);
        let mut d = Dvc::default();
        // Row 0: red literal, repeat-left x2, blue literal.
        // Row 1: copy-above x2, then a 2-colour bitmap 0b10 over (blue, red)
        // — left is blue, nearest different before it is red.
        let red = [0x80 | 0x7C, 0x00];
        let blue = [0x80, 0x1F];
        let mut s = Vec::new();
        s.extend_from_slice(&red);
        s.push(0x20 | 2);
        s.extend_from_slice(&blue);
        s.push(0x40 | 2);
        s.push(0x60 | 0b0100); // bits 0,1,0,0; only the first two land on screen
        assert!(!d.push(DVC15, &frag(4, 2, SOF, &s), &mut fb), "no REF: not started");
        assert!(d.push(DVC15, &frag(4, 2, SOF | EOF | REF, &s), &mut fb));
        let (r, b) = (0xF80000, 0x0000F8);
        assert_eq!(&fb.framebuffer[..4], &[r, r, r, b]);
        assert_eq!(&fb.framebuffer[4..6], &[r, r]);
        // The bitmap's first bit lands on pixel 6 (left = red, other = blue).
        assert_eq!(fb.framebuffer[6], r);
        assert_eq!(fb.framebuffer[7], b);

        // Next frame: skip everything but the last pixel, which turns red.
        let next = [0x00 | 7, red[0], red[1]];
        assert!(d.push(DVC15, &frag(4, 2, SOF | EOF, &next), &mut fb));
        assert_eq!(&fb.framebuffer[..8], &[r, r, r, b, r, r, r, r]);
    }

    #[test]
    fn run_lengths_continue_five_bits_at_a_time() {
        let mut fb = ast2100::Decoder::new(40, 1);
        let mut d = Dvc::default();
        // Literal, then repeat-left 1 + (1 << 5) = 33, then copy... skip 6.
        let s = [0x80 | 0x7C, 0x00, 0x20 | 1, 0x20 | 1, 0x00 | 6];
        assert!(d.push(DVC15, &frag(40, 1, SOF | EOF | REF, &s), &mut fb));
        assert!(fb.framebuffer[..34].iter().all(|&p| p == 0xF80000));
        assert!(fb.framebuffer[34..].iter().all(|&p| p == 0));
    }

    /// A hostile stream must neither panic nor run away: a run that never
    /// ends, and a screen of 2-colour bitmaps over one colour.
    #[test]
    fn hostile_streams_stay_bounded() {
        let mut fb = ast2100::Decoder::new(512, 512);
        let mut d = Dvc::default();
        let mut s = vec![0x80 | 0x7C, 0x00];
        s.extend(std::iter::repeat(0x20 | 0x1F).take(100_000));
        s.push(0x80);
        s.push(0x00);
        assert!(d.push(DVC15, &frag(512, 512, SOF | EOF | REF, &s), &mut fb));
        let mut s = Vec::new();
        s.extend(std::iter::repeat(0x23).take(100_000));
        assert!(d.push(DVC23X, &frag(512, 512, SOF | EOF | REF, &s), &mut fb));

        let (w, h) = (1024usize, 768usize);
        let mut fb = ast2100::Decoder::new(w, h);
        let mut d = Dvc::default();
        let s = vec![0x60u8; w * h / 4];
        let t = std::time::Instant::now();
        assert!(d.push(DVC15, &frag(w as u16, h as u16, SOF | EOF | REF, &s), &mut fb));
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
    }

    /// The incremental second-colour scan must agree with the reference's
    /// rescan from scratch, frame after frame.
    #[test]
    fn incremental_scan_matches_rescan() {
        let mut seed = 0x2545F4914F6CDD1Du64;
        let mut rnd = move || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed as u8 };
        let (w, h) = (64u16, 48u16);
        let (mut a, mut b) = (Dvc::default(), Dvc::default());
        b.naive = true;
        let (mut fa, mut fb) = (ast2100::Decoder::new(1, 1), ast2100::Decoder::new(1, 1));
        for frame in 0..200 {
            // Few colours and plenty of bitmaps, so scans run long and hit.
            let s: Vec<u8> = (0..3000).map(|_| match rnd() % 6 {
                0 => 0x80 | (rnd() & 0x03),
                1 => rnd() & 0x03,
                2 => 0x20 | (rnd() & 0x07),
                3 => 0x40 | (rnd() & 0x07),
                _ => 0x60 | (rnd() & 0x0F),
            }).collect();
            let flags = SOF | EOF | if frame == 0 { REF } else { 0 };
            a.push(DVC15, &frag(w, h, flags, &s), &mut fa);
            b.push(DVC15, &frag(w, h, flags, &s), &mut fb);
            assert_eq!(fa.framebuffer, fb.framebuffer, "frame {frame}");
        }
    }

    #[test]
    fn dvc7_palette_and_grey() {
        let mut fb = ast2100::Decoder::new(2, 1);
        let mut d = Dvc::default();
        // Index 64 maps to cube entry 100 = r 0, g 0, b 255 (index/25 = 4).
        assert!(d.push(DVC7, &frag(2, 1, SOF | EOF | REF, &[0x80 | 64, 0x80 | 127]), &mut fb));
        assert_eq!(fb.framebuffer[0], 0x0000FF);
        assert_eq!(fb.framebuffer[1], 0xdfdfdf);
        assert!(d.push(DVC7_GREY, &frag(2, 1, SOF | EOF | REF, &[0x80 | 0x40, 0x80]), &mut fb));
        assert_eq!(&fb.framebuffer[..], &[0x808080, 0]);
    }

    #[test]
    fn dvc23x_deltas() {
        let mut fb = ast2100::Decoder::new(2, 2);
        let mut d = Dvc::default();
        // Literal r=0x10 g=0x20 b=0x40; then left +1 red, -1 green, +2 blue;
        // then above -1 grey; then left +0.
        let lit = [0x80 | (0x10 >> 1), ((0x10 & 1) << 7) | (0x20 >> 1), ((0x20 & 1) << 7) | (0x40 >> 1)];
        let s = [lit[0], lit[1], lit[2], 0x30 | 1, 0xF2, 0x70 | 0xF, 0x60];
        assert!(d.push(DVC23X, &frag(2, 2, SOF | EOF | REF, &s), &mut fb));
        assert_eq!(fb.framebuffer[0], 0x102040);
        assert_eq!(fb.framebuffer[1], 0x111F42);
        assert_eq!(fb.framebuffer[2], 0x0F1F3E);
        assert_eq!(fb.framebuffer[3], 0x0F1F3E);
    }
}

/// The client-texture replay over the hand-built streams above, frame by
/// frame: blit's diff must mark every pixel it changed.
#[cfg(test)]
mod damage_replay {
    use super::*;
    use crate::damage::tests::Replay;

    fn frag(w: u16, h: u16, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p[4..6].copy_from_slice(&h.to_be_bytes());
        p[6..8].copy_from_slice(&w.to_be_bytes());
        p[8] = flags;
        p.extend_from_slice(data);
        p
    }

    #[test]
    fn hand_built_frames_replay() {
        let mut fb = ast2100::Decoder::new(4, 2);
        let mut d = Dvc::default();
        let mut rp = Replay::default();
        rp.step(&mut fb, "new");
        let (red, blue) = ([0x80 | 0x7C, 0x00], [0x80, 0x1F]);
        let mut s = Vec::new();
        s.extend_from_slice(&red);
        s.push(0x20 | 2);
        s.extend_from_slice(&blue);
        s.push(0x40 | 2);
        s.push(0x60 | 0b0100);
        assert!(d.push(DVC15, &frag(4, 2, SOF | EOF | REF, &s), &mut fb));
        rp.step(&mut fb, "first frame");
        let next = [7, red[0], red[1]];
        assert!(d.push(DVC15, &frag(4, 2, SOF | EOF, &next), &mut fb));
        rp.step(&mut fb, "skip then red");
        // The same frame again changes nothing on screen.
        assert!(d.push(DVC15, &frag(4, 2, SOF | EOF, &next), &mut fb));
        assert_eq!(rp.step(&mut fb, "static"), None);
    }

    #[test]
    fn random_frames_replay_with_partial_damage() {
        let mut seed = 0x2545F4914F6CDD1Du64;
        let mut rnd = move || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed as u8 };
        let (w, h) = (100u16, 70u16);
        let mut d = Dvc::default();
        let mut fb = ast2100::Decoder::new(1, 1);
        let mut rp = Replay::default();
        for frame in 0..60 {
            // A skip (consecutive skips would add up to one run past the
            // end), then a short burst of commands: a small change.
            let mut s: Vec<u8> = vec![rnd() & 0x1F];
            s.extend((0..20).map(|_| match rnd() % 4 {
                0 => 0x80 | (rnd() & 0x7F),
                1 => rnd(),
                2 => 0x20 | (rnd() & 0x07),
                _ => 0x40 | (rnd() & 0x07),
            }));
            let flags = SOF | EOF | if frame == 0 { REF } else { 0 };
            assert!(d.push(DVC15, &frag(w, h, flags, &s), &mut fb));
            rp.step(&mut fb, &format!("frame {frame}"));
        }
        assert!(rp.partial > 30, "only {} partial frames", rp.partial);
    }
}
