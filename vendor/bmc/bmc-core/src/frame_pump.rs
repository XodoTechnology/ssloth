//! From a session's decoder damage to what a front end paints.
//!
//! One `FramePump` per session is the only caller of
//! `ast2100::Decoder::take_dirty`, so the damage has exactly one consumer
//! whichever front end draws it. It has two outputs over that one damage set:
//! [`FramePump::pull_wire`], the KVMF frame a webview paints, and
//! [`FramePump::pull_rects`], the merged rectangles and the framebuffer itself
//! for a native painter (egui), which would gain only a copy and a format
//! conversion from encoding a frame to decode it again in the same process.
//!
//! The pump has no timer or thread of its own: a front end pulls when it is
//! about to paint, and only the visible tab pulls. A tab that stops pulling
//! stops all encoding work, while its damage waits in the decoder's tile
//! bitset, which is sized to the frame and so cannot grow.
//!
//! The wire format:
//!
//! ```text
//! header, 16 bytes, little-endian
//!   0  "KVMF"
//!   4  u8  version (1)
//!   5  u8  flags: 1 FULL (every tile is in it), 2 RESIZED (reallocate first)
//!   6  u16 rect count
//!   8  u32 sequence number
//!   12 u16 framebuffer width
//!   14 u16 framebuffer height
//! rect table, 16 bytes each
//!   0  u16 x, u16 y, u16 w, u16 h
//!   8  u8  format (0 BGRX, 1 RGB5551), 3 bytes zero
//!   12 u32 byte length of the pixel data
//! pixel data, one block per rect in table order, each padded to 4 bytes
//! ```
//!
//! `ui/src/lib/console/frames.ts` decodes the same layout, and the golden frame
//! in `ui/src/lib/console/frame-golden.txt` is checked by both sides.

use std::sync::{Arc, Mutex};

use crate::ast2100;
use crate::damage::{Rect, Tiles};

pub const MAGIC: &[u8; 4] = b"KVMF";
pub const VERSION: u8 = 1;
pub const HEADER: usize = 16;
pub const RECT_ENTRY: usize = 16;
pub const FLAG_FULL: u8 = 1;
pub const FLAG_RESIZED: u8 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    /// 0x00RRGGBB as stored: little-endian bytes B,G,R,X, swizzled in the
    /// shader. Exact for every source.
    Bgrx = 0,
    /// R5 G5 B5 A1, the layout `GL_UNSIGNED_SHORT_5_5_5_1` takes. Half the
    /// bytes of BGRX, and exact for 15-bit sources that bit-replicate (X9's
    /// raw path); not 565, which tints X9's grey. The default (spike S1).
    #[default]
    Rgb5551 = 1,
}

impl Format {
    pub fn from_wire(v: u8) -> Option<Self> {
        match v {
            0 => Some(Format::Bgrx),
            1 => Some(Format::Rgb5551),
            _ => None,
        }
    }

    pub fn bytes_per_pixel(self) -> usize {
        match self {
            Format::Bgrx => 4,
            Format::Rgb5551 => 2,
        }
    }
}

pub fn to_5551(p: u32) -> u16 {
    (((p >> 8) & 0xF800) | ((p >> 5) & 0x07C0) | ((p >> 2) & 0x003E) | 1) as u16
}

/// The expansion the GPU applies when it samples an RGB5_A1 texture (bit
/// replication); the Canvas2D painter uses the same, so both paint alike.
pub fn from_5551(v: u16) -> u32 {
    let e = |c: u16| -> u32 {
        let c = u32::from(c & 31);
        (c << 3) | (c >> 2)
    };
    (e(v >> 11) << 16) | (e(v >> 6) << 8) | e(v >> 1)
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Encode `rects` of a `width` x `height` framebuffer as one KVMF frame.
pub fn encode(fb: &[u32], width: usize, height: usize, rects: &[Rect], full: bool, resized: bool, seq: u32, fmt: Format) -> Vec<u8> {
    let bpp = fmt.bytes_per_pixel();
    let data: usize = rects.iter().map(|r| pad4(r.w * r.h * bpp)).sum();
    let mut out = Vec::with_capacity(HEADER + RECT_ENTRY * rects.len() + data);
    let flags = if full { FLAG_FULL } else { 0 } | if resized { FLAG_RESIZED } else { 0 };
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&(rects.len() as u16).to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&(width as u16).to_le_bytes());
    out.extend_from_slice(&(height as u16).to_le_bytes());
    for r in rects {
        for v in [r.x, r.y, r.w, r.h] {
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        out.extend_from_slice(&[fmt as u8, 0, 0, 0]);
        out.extend_from_slice(&((r.w * r.h * bpp) as u32).to_le_bytes());
    }
    for r in rects {
        let start = out.len();
        for y in r.y..r.y + r.h {
            let row = &fb[y * width + r.x..y * width + r.x + r.w];
            match fmt {
                Format::Bgrx => row.iter().for_each(|p| out.extend_from_slice(&p.to_le_bytes())),
                Format::Rgb5551 => row.iter().for_each(|&p| out.extend_from_slice(&to_5551(p).to_le_bytes())),
            }
        }
        out.resize(start + pad4(out.len() - start), 0);
    }
    out
}

/// A KVMF frame as a page reads it, for checks that paint a client copy the
/// way `frames.ts` does.
#[derive(Debug)]
pub struct Decoded {
    pub flags: u8,
    pub seq: u32,
    pub width: usize,
    pub height: usize,
    /// x, y, w, h, format, pixel data.
    pub rects: Vec<(usize, usize, usize, usize, u8, Vec<u8>)>,
}

/// Read a KVMF frame. Panics on a malformed one: this is the checking side.
pub fn decode(b: &[u8]) -> Decoded {
    let u16at = |o: usize| usize::from(u16::from_le_bytes([b[o], b[o + 1]]));
    let u32at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    assert_eq!(&b[0..4], MAGIC);
    assert_eq!(b[4], VERSION);
    let n = u16at(6);
    let mut off = HEADER + RECT_ENTRY * n;
    let mut rects = Vec::new();
    for i in 0..n {
        let e = HEADER + RECT_ENTRY * i;
        let len = u32at(e + 12) as usize;
        rects.push((u16at(e), u16at(e + 2), u16at(e + 4), u16at(e + 6), b[e + 8], b[off..off + len].to_vec()));
        off += pad4(len);
    }
    assert_eq!(off, b.len());
    Decoded { flags: b[5], seq: u32at(8), width: u16at(12), height: u16at(14), rects }
}

/// Paint a decoded frame into a client-side copy `width` wide, as the page does.
pub fn paint(client: &mut [u32], width: usize, d: &Decoded) {
    for (x, y, w, h, fmt, data) in &d.rects {
        for row in 0..*h {
            for col in 0..*w {
                let i = row * w + col;
                client[(y + row) * width + x + col] = match *fmt {
                    0 => u32::from_le_bytes([data[i * 4], data[i * 4 + 1], data[i * 4 + 2], 0]),
                    _ => from_5551(u16::from_le_bytes([data[i * 2], data[i * 2 + 1]])),
                };
            }
        }
    }
}

pub struct FramePump {
    decoder: Arc<Mutex<ast2100::Decoder>>,
    /// Damage taken from the decoder and not yet pulled, at the frame's size.
    pending: Tiles,
    resized: bool,
    seq: u32,
}

impl FramePump {
    /// The pump for one session's decoder. Its first pull is a full frame
    /// that tells the client to allocate.
    pub fn new(decoder: Arc<Mutex<ast2100::Decoder>>) -> Self {
        FramePump { decoder, pending: Tiles::new(0, 0), resized: true, seq: 0 }
    }

    pub fn decoder(&self) -> &Arc<Mutex<ast2100::Decoder>> {
        &self.decoder
    }

    /// Make the next pull a full frame: a tab switch, a thumbnail, anything
    /// that cannot trust what the client holds.
    pub fn request_full(&mut self) {
        self.pending.mark_all();
    }

    /// A new client (a new socket is a new texture): the next pull is a full
    /// frame that also tells it to allocate.
    pub fn new_client(&mut self) {
        self.request_full();
        self.resized = true;
    }

    /// Take the decoder's damage into `pending`. Called under its lock.
    fn fold(&mut self, d: &mut ast2100::Decoder) {
        let dmg = d.take_dirty();
        if self.pending.size() != (d.width, d.height) || dmg.as_ref().is_some_and(|g| g.resized) {
            // A new geometry: whatever was pending described the old frame.
            self.pending = Tiles::new(d.width, d.height);
            self.pending.mark_all();
            self.resized = true;
        } else if let Some(dmg) = dmg {
            for r in &dmg.rects {
                self.pending.mark(r.x, r.y, r.w, r.h);
            }
        }
    }

    /// The pending damage as one KVMF frame in `fmt`, or None when nothing
    /// changed. Each frame gets the next sequence number.
    pub fn pull_wire(&mut self, fmt: Format) -> Option<Vec<u8>> {
        let decoder = self.decoder.clone();
        let mut d = decoder.lock().unwrap();
        self.fold(&mut d);
        if !self.pending.is_dirty() {
            return None;
        }
        let rects = self.pending.rects();
        let out = encode(&d.framebuffer, d.width, d.height, &rects, self.pending.all_dirty(), self.resized, self.seq, fmt);
        self.seq = self.seq.wrapping_add(1);
        self.pending.clear();
        self.resized = false;
        Some(out)
    }

    /// Hand the pending damage to a native painter: `paint(framebuffer,
    /// width, rects, resized)`, under the decoder's lock, once per pull. None
    /// (and no call) when nothing changed.
    pub fn pull_rects<R>(&mut self, paint: impl FnOnce(&[u32], usize, &[Rect], bool) -> R) -> Option<R> {
        let decoder = self.decoder.clone();
        let mut d = decoder.lock().unwrap();
        self.fold(&mut d);
        if !self.pending.is_dirty() {
            return None;
        }
        let rects = self.pending.rects();
        let r = paint(&d.framebuffer, d.width, &rects, self.resized);
        self.pending.clear();
        self.resized = false;
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pump(w: usize, h: usize) -> (FramePump, Arc<Mutex<ast2100::Decoder>>) {
        let d = Arc::new(Mutex::new(ast2100::Decoder::new(w, h)));
        (FramePump::new(d.clone()), d)
    }

    /// Values that survive 5 bits and bit replication unchanged.
    const EXACT: [u32; 8] = [0x000000, 0xFFFFFF, 0xADADAD, 0xDE2121, 0x21AD42, 0x2142DE, 0xFFCE00, 0xCE00CE];

    #[test]
    fn bgrx_round_trips_every_pixel() {
        let (mut p, d) = pump(70, 40);
        for (i, px) in d.lock().unwrap().framebuffer.iter_mut().enumerate() {
            *px = (i as u32).wrapping_mul(2_654_435_761) & 0x00FF_FFFF;
        }
        let want = d.lock().unwrap().framebuffer.clone();
        let f = decode(&p.pull_wire(Format::Bgrx).unwrap());
        let mut client = vec![0; 70 * 40];
        paint(&mut client, 70, &f);
        assert_eq!(client, want);
    }

    #[test]
    fn rgb5551_round_trips_known_pixels() {
        let (mut p, d) = pump(64, 32);
        for (i, px) in d.lock().unwrap().framebuffer.iter_mut().enumerate() {
            *px = EXACT[i % EXACT.len()];
        }
        let want = d.lock().unwrap().framebuffer.clone();
        let f = decode(&p.pull_wire(Format::Rgb5551).unwrap());
        let mut client = vec![0; 64 * 32];
        paint(&mut client, 64, &f);
        assert_eq!(client, want);
    }

    #[test]
    fn x9_grey_stays_neutral() {
        // CLAUDE.md: read as 565 this comes back (80, 212, 168).
        let v = to_5551(0x00AD_ADAD);
        assert_eq!(((v >> 11) & 31, (v >> 6) & 31, (v >> 1) & 31, v & 1), (21, 21, 21, 1));
        assert_eq!(from_5551(v), 0x00AD_ADAD);
    }

    #[test]
    fn every_rgb555_value_is_exact() {
        for v in 0..0x8000u16 {
            let (r, g, b) = ast2100::rgb555(v);
            let p = (r << 16) | (g << 8) | b;
            assert_eq!(from_5551(to_5551(p)), p, "0x{v:04x}");
        }
    }

    #[test]
    fn bgrx_is_exact_for_24_bit() {
        let mut fb = Vec::new();
        for c in 0..256u32 {
            fb.extend([c << 16, c << 8, c, (c << 16) | ((255 - c) << 8) | (c ^ 0x5A)]);
        }
        let rects = [Rect { x: 0, y: 0, w: 4, h: 256 }];
        let f = decode(&encode(&fb, 4, 256, &rects, true, false, 0, Format::Bgrx));
        let mut client = vec![0; fb.len()];
        paint(&mut client, 4, &f);
        assert_eq!(client, fb);
    }

    /// avct_dvc expands 15-bit colour as `c << 3` without replication, so
    /// RGB5551 paints it up to 7 brighter per channel (plan Decision 6).
    #[test]
    fn avct_15_bit_error_is_bounded() {
        let mut worst = 0;
        for c in 0..32u32 {
            let p = (c << 19) | (c << 11) | (c << 3);
            let back = from_5551(to_5551(p));
            for shift in [16, 8, 0] {
                let (a, b) = ((p >> shift) & 0xFF, (back >> shift) & 0xFF);
                assert!(b >= a && b - a <= 7, "{c}: {a} -> {b}");
                worst = worst.max(b - a);
            }
        }
        assert_eq!(worst, 7);
    }

    #[test]
    fn a_resize_sends_a_full_frame_at_the_new_size() {
        let (mut p, d) = pump(720, 400);
        p.pull_wire(Format::Rgb5551).unwrap();
        assert!(p.pull_wire(Format::Rgb5551).is_none());
        d.lock().unwrap().resize(1024, 768);
        let f = decode(&p.pull_wire(Format::Rgb5551).unwrap());
        assert_eq!(f.flags, FLAG_FULL | FLAG_RESIZED);
        assert_eq!((f.width, f.height), (1024, 768));
        assert_eq!(f.rects.iter().map(|r| r.2 * r.3).sum::<usize>(), 1024 * 768);
    }

    #[test]
    fn header_round_trips() {
        let (mut p, d) = pump(1000, 700);
        p.seq = 0xDEAD_BEEF;
        let f = decode(&p.pull_wire(Format::Rgb5551).unwrap());
        assert_eq!((f.flags, f.seq, f.width, f.height), (FLAG_FULL | FLAG_RESIZED, 0xDEAD_BEEF, 1000, 700));
        assert_eq!(f.rects.len(), 1);
        d.lock().unwrap().mark(40, 40, 1, 1);
        let f = decode(&p.pull_wire(Format::Bgrx).unwrap());
        assert_eq!((f.flags, f.seq), (0, 0xDEAD_BEF0));
        let r = &f.rects[0];
        assert_eq!((r.0, r.1, r.2, r.3, r.4, r.5.len()), (32, 32, 32, 32, 0, 32 * 32 * 4));
        assert!(p.pull_wire(Format::Bgrx).is_none());
    }

    /// The frame both sides must encode byte for byte (frame-golden.txt).
    fn golden_frame() -> Vec<u8> {
        let (mut p, d) = pump(40, 34);
        p.pull_wire(Format::Rgb5551);
        p.seq = 7;
        {
            let mut d = d.lock().unwrap();
            d.framebuffer[0] = 0xADADAD;
            d.framebuffer[33 * 40 + 39] = 0xDE2121;
            d.mark(0, 0, 1, 1);
            d.mark(39, 33, 1, 1);
        }
        p.pull_wire(Format::Rgb5551).unwrap()
    }

    fn fnv(px: &[u32]) -> u32 {
        let mut h: u32 = 0x811C_9DC5;
        for b in px.iter().flat_map(|p| p.to_le_bytes()) {
            h ^= u32::from(b);
            h = h.wrapping_mul(0x0100_0193);
        }
        h
    }

    #[test]
    fn golden_frame_matches_ui() {
        let golden = include_str!("../../../ui/src/lib/console/frame-golden.txt");
        let get = |k: &str| golden.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(' '))).unwrap().to_string();
        let f = golden_frame();
        let n = usize::from(u16::from_le_bytes([f[6], f[7]]));
        let head: String = f[..HEADER + RECT_ENTRY * n].iter().map(|b| format!("{b:02x}")).collect();
        let words: Vec<u32> = f.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        assert_eq!(head, get("header"));
        assert_eq!(format!("{:08x}", fnv(&words)), get("frame_fnv"));
    }

    #[test]
    fn damage_accumulates_between_pulls() {
        let (mut p, d) = pump(200, 100);
        p.pull_wire(Format::Bgrx).unwrap();
        d.lock().unwrap().mark(0, 0, 1, 1);
        // A second decode, untaken, while nobody pulls.
        d.lock().unwrap().mark(150, 70, 1, 1);
        let f = decode(&p.pull_wire(Format::Bgrx).unwrap());
        let at: Vec<_> = f.rects.iter().map(|r| (r.0, r.1)).collect();
        assert_eq!(at, [(0, 0), (128, 64)]);
        assert_eq!(f.flags, 0);
    }

    #[test]
    fn damage_taken_between_pulls_is_kept() {
        // A pull of one output folds damage the other output then reports.
        let (mut p, d) = pump(64, 64);
        p.pull_rects(|_, _, _, _| ()).unwrap();
        d.lock().unwrap().mark(0, 0, 1, 1);
        let rects = p.pull_rects(|_, _, r, resized| (r.to_vec(), resized)).unwrap();
        assert_eq!(rects, (vec![Rect { x: 0, y: 0, w: 32, h: 32 }], false));
        assert!(p.pull_rects(|_, _, _, _| ()).is_none());
    }

    #[test]
    fn request_full_marks_everything() {
        let (mut p, _d) = pump(100, 100);
        p.pull_wire(Format::Bgrx).unwrap();
        p.request_full();
        let f = decode(&p.pull_wire(Format::Bgrx).unwrap());
        assert_eq!(f.flags, FLAG_FULL);
        assert_eq!(f.rects.len(), 1);
    }

    #[test]
    fn a_new_client_gets_full_and_resized() {
        let (mut p, _d) = pump(100, 100);
        p.pull_wire(Format::Bgrx).unwrap();
        p.new_client();
        assert_eq!(decode(&p.pull_wire(Format::Bgrx).unwrap()).flags, FLAG_FULL | FLAG_RESIZED);
    }

    #[test]
    fn no_damage_no_frame() {
        let (mut p, _d) = pump(100, 100);
        assert!(p.pull_rects(|_, _, _, resized| assert!(resized)).is_some());
        assert!(p.pull_wire(Format::Rgb5551).is_none());
        assert!(p.pull_rects(|_, _, _, _| ()).is_none());
    }

    /// Task 5's replay, through the wire: a client that only ever paints
    /// pulled frames ends up with the decoder's picture after every step.
    #[test]
    fn replay_through_the_wire() {
        use crate::vnc;
        let (mut p, d) = pump(120, 90);
        let mut client = Vec::new();
        let mut step = |p: &mut FramePump, what: &str| {
            if let Some(b) = p.pull_wire(Format::Bgrx) {
                let f = decode(&b);
                if f.flags & FLAG_RESIZED != 0 {
                    client = vec![0xFF00_FF00; f.width * f.height];
                }
                paint(&mut client, f.width, &f);
            }
            assert_eq!(client, d.lock().unwrap().framebuffer, "{what}");
        };
        step(&mut p, "first");

        // RFB: a raw rectangle, then a CopyRect overlapping it, then DesktopSize.
        let format = vnc::PixelFormat {
            bits_per_pixel: 32, depth: 24, big_endian: false, true_colour: true,
            red_max: 255, green_max: 255, blue_max: 255, red_shift: 16, green_shift: 8, blue_shift: 0,
        };
        let mut v = vnc::Decoder::new(format, false);
        let rect = |x: u16, y: u16, w: u16, h: u16, enc: i32, body: &[u8]| {
            let mut m = vec![0u8, 0, 0, 1];
            for n in [x, y, w, h] {
                m.extend_from_slice(&n.to_be_bytes());
            }
            m.extend_from_slice(&enc.to_be_bytes());
            m.extend_from_slice(body);
            m
        };
        let raw: Vec<u8> = (0..30 * 20u32).flat_map(|i| (i.wrapping_mul(2_654_435_761) & 0xFF_FFFF).to_le_bytes()).collect();
        v.feed(&rect(10, 10, 30, 20, vnc::ENC_RAW, &raw), &mut d.lock().unwrap()).unwrap();
        step(&mut p, "raw");
        v.feed(&rect(25, 15, 30, 20, vnc::ENC_COPYRECT, &[0, 10, 0, 10]), &mut d.lock().unwrap()).unwrap();
        step(&mut p, "copyrect");
        v.feed(&rect(0, 0, 64, 48, vnc::ENC_DESKTOP_SIZE, &[]), &mut d.lock().unwrap()).unwrap();
        step(&mut p, "desktop size");

        // AST2100: X9 raw RGB555 rectangles on the new screen.
        let mut data = vec![0u8; 6];
        data.extend((0..16 * 9u16).flat_map(|i| (i.wrapping_mul(331) & 0x7FFF).to_le_bytes()));
        d.lock().unwrap().decode_rect(40, 30, 16, 9, 0x59, 0, &data);
        step(&mut p, "x9 raw");
    }
}
