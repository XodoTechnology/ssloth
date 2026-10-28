//! AST2100 (ASPEED) video decoder — a faithful port of the vendor client
//! novnc-ref/ast2100.js. JPEG-family codec (Huffman -> dezigzag -> dequant ->
//! IDCT -> YCbCr->RGB) plus a VQ (vector-quantization) block mode.
//!
//! The JS uses `<<` / `>>>` on 32-bit values whose shift counts are taken mod
//! 32. Rust's wrapping_shl/wrapping_shr match that, so all bit-window
//! arithmetic below uses them to stay bit-exact with the reference. The dequant
//! multiply is done in i64 (JS uses f64) to avoid overflow.

use crate::damage::{Damage, Tiles};
use crate::tables;

/// Unpack one X1R5G5B5 pixel to 8-bit RGB.
///
/// The X9 generation sends 16-bit pixels as 555 with the top bit unused, not as
/// 565. Reading them as 565 borrows the low bit of red into green and shifts
/// everything down a bit, which turns neutral greys green — a mid grey comes out
/// (80, 212, 168) instead of (173, 173, 173). Confirmed against the same BMC's
/// own BMP snapshot, which is BI_RGB 16bpp and therefore 555 by definition.
///
/// Each channel is widened by replicating its high bits, so full scale reaches
/// 0xFF rather than 0xF8.
pub(crate) fn rgb555(v: u16) -> (u32, u32, u32) {
    let e = |c: u16| (((c << 3) | (c >> 2)) & 0xFF) as u32;
    (e((v >> 10) & 0x1F), e((v >> 5) & 0x1F), e(v & 0x1F))
}

const NEG_POW2: [i32; 16] = [
    0, -1, -3, -7, -15, -31, -63, -127, -255, -511, -1023, -2047, -4095, -8191, -16383, -32767,
];
const SCALEFACTOR: [f64; 8] = [
    1.0, 1.387039845, 1.306562965, 1.175875602, 1.0, 0.785694958, 0.5411961, 0.275899379,
];

const JPEG_NO_SKIP_CODE: u32 = 0;
const JPEG_SKIP_CODE: u32 = 8;
/// Second-pass refinement of a block already drawn: a residual added to the
/// YUV the first pass left there. AST2300's encoder emits these; the AST2100
/// decoder this one began as never did.
const JPEG_NO_SKIP_PASS2_CODE: u32 = 2;
const JPEG_SKIP_PASS2_CODE: u32 = 10;
const FRAME_END_CODE: u32 = 9;
const VQ_NO_SKIP_1: u32 = 5;
const VQ_NO_SKIP_2: u32 = 6;
const VQ_NO_SKIP_4: u32 = 7;
const VQ_SKIP_1: u32 = 13;
const VQ_SKIP_2: u32 = 14;
const VQ_SKIP_4: u32 = 15;

const VQ_INDEX_MASK: u32 = 3;
const VQ_COLOR_MASK: u32 = 0x00ff_ffff;
const VQ_HEADER_MASK: u32 = 1;

const RLIMIT_OFF: i32 = 256; // mRlimitTable_index

struct HuffTable {
    table_length: [i32; 17],
    v: Vec<u8>,
    minor_code: [i32; 17],
    table_len: Vec<u8>,
}

impl HuffTable {
    fn build(nrcode: &[i32], value: &[i32], huff_code: &[i32]) -> HuffTable {
        let mut t = HuffTable {
            table_length: [0; 17],
            v: vec![0u8; 65536],
            minor_code: [0; 17],
            table_len: vec![0u8; 65536],
        };
        for j in 1..=16 {
            t.table_length[j] = nrcode[j];
        }
        let mut i = 0usize;
        for k in 1..=16usize {
            for j in 0..t.table_length[k] {
                t.v[word_hi_lo(k as u32, j as u32) as usize] = value[i] as u8;
                i += 1;
            }
        }
        let mut code: i64 = 0;
        for k in 1..=16usize {
            t.minor_code[k] = (code as u32 & 0xffff) as i32;
            for _ in 1..=t.table_length[k] {
                code += 1;
            }
            code = code.wrapping_mul(2);
            if t.table_length[k] == 0 {
                t.minor_code[k] = 0xffff;
            }
        }
        t.table_len[0] = 2;
        let mut ii = 2usize;
        for code_index in 1..65535i64 {
            if code_index < huff_code[ii] as i64 {
                t.table_len[code_index as usize] = (huff_code[ii + 1] & 0xff) as u8;
            } else {
                ii += 2;
                t.table_len[code_index as usize] = (huff_code[ii + 1] & 0xff) as u8;
            }
        }
        t
    }
}

fn word_hi_lo(hi: u32, lo: u32) -> u32 {
    hi.wrapping_add(lo << 8)
}

struct VqColor {
    index: [usize; 4],
    color: [u32; 4],
    bitmap_bits: u32,
}

pub struct Decoder {
    pub width: usize,
    pub height: usize,
    pub framebuffer: Vec<u32>,
    /// Telemetry: decoded frames and compressed bytes consumed.
    pub frames: u64,
    pub bytes_in: u64,
    /// The 32x32 tiles written since the damage was last taken, so a front end
    /// uploads those rather than the whole screen. Every writer marks what it
    /// draws: this decoder's own paths, and the RFB and DVC decoders that fill
    /// `framebuffer` directly.
    tiles: Tiles,
    /// The geometry changed since the damage was last taken.
    resized: bool,

    buffer: Vec<u8>,
    index: usize,
    codebuf: u32,
    newbuf: u32,
    newbits: i32,

    mode420: bool,
    grey: bool,
    tmp_w: usize,
    tmp_h: usize,
    txb: usize,
    tyb: usize,
    dc_y: i32,
    dc_cb: i32,
    dc_cr: i32,
    previous_dc: i32,

    htdc: [HuffTable; 2],
    htac: [HuffTable; 2],
    /// Quantisation tables: pass-1 luma and chroma, then pass-2 luma and chroma.
    mqt: [[i64; 64]; 4],
    /// Per-pixel Y, Cb, Cr as the last pass-1 block left it — what a pass-2
    /// block refines.
    prev_yuv: Vec<u8>,

    dct_coeff: [i32; 384],
    tile_yuv: [i32; 768],

    m_y: [i32; 256],
    cr_to_r: [i32; 256],
    cb_to_b: [i32; 256],
    cr_to_g: [i32; 256],
    cb_to_g: [i32; 256],
    rlimit: Vec<i32>,

    vq: VqColor,
    y_sel: usize,
    uv_sel: usize,
    old_y_sel: i32,
}

impl Decoder {
    pub fn new(width: usize, height: usize) -> Self {
        let htdc = [
            HuffTable::build(&tables::STD_DC_LUMINANCE_NRCODES, &tables::STD_DC_LUMINANCE_VALUES, &tables::DC_LUMINANCE_HUFFMANCODE),
            HuffTable::build(&tables::STD_DC_CHROMINANCE_NRCODES, &tables::STD_DC_CHROMINANCE_VALUES, &tables::DC_CHROMINANCE_HUFFMANCODE),
        ];
        let htac = [
            HuffTable::build(&tables::STD_AC_LUMINANCE_NRCODES, &tables::STD_AC_LUMINANCE_VALUES, &tables::AC_LUMINANCE_HUFFMANCODE),
            HuffTable::build(&tables::STD_AC_CHROMINANCE_NRCODES, &tables::STD_AC_CHROMINANCE_VALUES, &tables::AC_CHROMINANCE_HUFFMANCODE),
        ];
        let mut d = Decoder {
            width, height,
            framebuffer: vec![0; width * height],
            frames: 0,
            bytes_in: 0,
            // A new decoder's picture is news to every client.
            tiles: { let mut t = Tiles::new(width, height); t.mark_all(); t },
            resized: true,
            buffer: Vec::new(), index: 0, codebuf: 0, newbuf: 0, newbits: 0,
            mode420: true, grey: false, tmp_w: width, tmp_h: height,
            txb: 0, tyb: 0, dc_y: 0, dc_cb: 0, dc_cr: 0, previous_dc: 0,
            htdc, htac, mqt: [[0; 64]; 4], prev_yuv: vec![0; width * height * 3],
            dct_coeff: [0; 384], tile_yuv: [0; 768],
            m_y: [0; 256], cr_to_r: [0; 256], cb_to_b: [0; 256],
            cr_to_g: [0; 256], cb_to_g: [0; 256], rlimit: vec![0; 1408],
            vq: VqColor { index: [0, 1, 2, 3], color: [0; 4], bitmap_bits: 0 },
            y_sel: 4, uv_sel: 7, old_y_sel: -1,
        };
        d.init_color_table();
        d.prepare_range_limit_table();
        d
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.framebuffer = vec![0; width * height];
        self.prev_yuv = vec![0; width * height * 3];
        self.old_y_sel = -1;
        self.new_geometry();
    }

    /// The frame is a new size: everything is damage, and a client must
    /// reallocate before painting.
    fn new_geometry(&mut self) {
        self.tiles = Tiles::new(self.width, self.height);
        self.tiles.mark_all();
        self.resized = true;
    }

    /// Record that `w` x `h` pixels at (x, y) changed. Anything that writes
    /// `framebuffer` must call this for what it wrote, or a client keeps the
    /// old pixels there.
    pub fn mark(&mut self, x: usize, y: usize, w: usize, h: usize) {
        self.tiles.mark(x, y, w, h);
    }

    pub fn mark_all(&mut self) {
        self.tiles.mark_all();
    }

    /// Mark exactly the tiles where `src` differs from the framebuffer, and
    /// copy it in: for a writer that redraws the whole picture every time.
    pub fn write_diff(&mut self, src: &[u32]) {
        self.tiles.diff_from(&mut self.framebuffer, src, self.width);
    }

    /// The damage since the last call, or None if nothing changed. It clears
    /// the damage, so one consumer must own it: `FramePump`, one per session,
    /// is the only caller, and front ends take their damage from that.
    pub fn take_dirty(&mut self) -> Option<Damage> {
        if !self.tiles.is_dirty() && !self.resized {
            return None;
        }
        let d = Damage { rects: self.tiles.rects(), full: self.tiles.all_dirty(), resized: self.resized };
        self.tiles.clear();
        self.resized = false;
        Some(d)
    }

    fn init_color_table(&mut self) {
        let n_scale = 65536.0f64;
        let n_half = 32768i64;
        let fix = |x: f64| (x * n_scale + 0.5) as i64;
        let mut x = -128i64;
        for i in 0..256 {
            self.cr_to_r[i] = ((fix(1.597656) * x + n_half) >> 16) as i32;
            self.cb_to_b[i] = ((fix(2.015625) * x + n_half) >> 16) as i32;
            self.cr_to_g[i] = ((-fix(0.8125) * x + n_half) >> 16) as i32;
            self.cb_to_g[i] = ((-fix(0.390625) * x + n_half) >> 16) as i32;
            x += 1;
        }
        let mut x = -16i64;
        for i in 0..256 {
            self.m_y[i] = ((fix(1.164) * x + n_half) >> 16) as i32;
            x += 1;
        }
    }

    fn prepare_range_limit_table(&mut self) {
        let idx = RLIMIT_OFF as usize;
        self.rlimit = vec![0; 1408];
        for j in 0..256 { self.rlimit[idx + j] = j as i32; }
        for j in 256..640 { self.rlimit[idx + j] = 255; }
        // j+640 => 0 (already zero); j+1024 => 0..128
        for j in 0..128 { self.rlimit[idx + j + 1024] = j as i32; }
    }

    fn quant_basic(sel: usize, chroma: bool) -> &'static [i32; 64] {
        macro_rules! t { ($n:ident) => { &tables::$n }; }
        if !chroma {
            match sel {
                0 => t!(TBL_000Y), 1 => t!(TBL_014Y), 2 => t!(TBL_029Y), 3 => t!(TBL_043Y),
                4 => t!(TBL_057Y), 5 => t!(TBL_071Y), 6 => t!(TBL_086Y), 7 => t!(TBL_100Y),
                8 => t!(TBL_Q08Y), 9 => t!(TBL_Q09Y), 10 => t!(TBL_Q10Y), _ => t!(TBL_Q11Y),
            }
        } else {
            match sel {
                0 => t!(TBL_000UV), 1 => t!(TBL_014UV), 2 => t!(TBL_029UV), 3 => t!(TBL_043UV),
                4 => t!(TBL_057UV), 5 => t!(TBL_071UV), 6 => t!(TBL_086UV), 7 => t!(TBL_100UV),
                8 => t!(TBL_Q08UV), 9 => t!(TBL_Q09UV), 10 => t!(TBL_Q10UV), _ => t!(TBL_Q11UV),
            }
        }
    }

    fn load_quant(&mut self, chroma: bool) {
        let sel = if chroma { self.uv_sel } else { self.y_sel };
        self.load_quant_into(if chroma { 1 } else { 0 }, sel, chroma);
    }

    /// Build quantisation table `dst` from the luma or chroma table set.
    fn load_quant_into(&mut self, dst: usize, sel: usize, chroma: bool) {
        let basic = Self::quant_basic(sel, chroma);
        let mut tempqt = [0u8; 64];
        for i in 0..64 {
            let mut temp = basic[i]; // basic*16/16
            if temp <= 0 { temp = 1; }
            if temp > 255 { temp = 255; }
            tempqt[tables::ZIGZAG[i] as usize] = (temp & 0xff) as u8;
        }
        let mut q = [0i64; 64];
        for j in 0..64 {
            q[j] = tempqt[tables::ZIGZAG[j] as usize] as i64;
        }
        let mut j = 0usize;
        for row in 0..8 {
            for col in 0..8 {
                let v = q[j] as f64 * SCALEFACTOR[row] * SCALEFACTOR[col] * 65536.0;
                self.mqt[dst][j] = v as i64;
                j += 1;
            }
        }
    }

    fn get_qbytes(&mut self, len: usize) -> u32 {
        let mut codebuf: u32 = 0;
        for i in 0..len {
            if self.index < self.buffer.len() {
                codebuf |= (self.buffer[self.index] as u32).wrapping_shl(8 * i as u32);
                self.index += 1;
            }
        }
        codebuf
    }

    fn updatereadbuf(&mut self, walks: u32) {
        let newbits = self.newbits - walks as i32;
        if newbits <= 0 {
            let readbuf = self.get_qbytes(4);
            self.codebuf = self.codebuf.wrapping_shl(walks)
                | (self.newbuf | readbuf.wrapping_shr(self.newbits as u32)).wrapping_shr(32 - walks);
            self.newbuf = readbuf.wrapping_shl((walks as i32 - self.newbits) as u32);
            self.newbits = 32 + newbits;
        } else {
            self.codebuf = self.codebuf.wrapping_shl(walks) | self.newbuf.wrapping_shr(32 - walks);
            self.newbuf = self.newbuf.wrapping_shl(walks);
            self.newbits = newbits;
        }
    }

    fn skip_kbits(&mut self, k: u32) { self.updatereadbuf(k); }

    fn get_kbits(&mut self, k: u32) -> i32 {
        let mut v = (0xffff & self.codebuf.wrapping_shr(32 - k)) as i32;
        if (1i32 << (k - 1)) & v == 0 {
            v += NEG_POW2[k as usize];
        }
        self.skip_kbits(k);
        v
    }

    fn process_huffman_data_unit(&mut self, dc_nr: usize, ac_nr: usize, previous_dc: i32, position: usize) {
        let k = self.htdc[dc_nr].table_len[(self.codebuf.wrapping_shr(16)) as usize] as u32;
        let tmp_hcode = (0xffff & self.codebuf.wrapping_shr(32 - k)) as i32;
        self.skip_kbits(k);
        let min = self.htdc[dc_nr].minor_code[k as usize];
        let size_val = self.htdc[dc_nr].v[word_hi_lo(k, (tmp_hcode - min) as u32) as usize] as u32;
        if size_val == 0 {
            self.dct_coeff[position] = previous_dc;
            self.previous_dc = previous_dc;
        } else {
            let add = self.get_kbits(size_val);
            self.dct_coeff[position] = previous_dc + add;
            self.previous_dc = self.dct_coeff[position];
        }
        let mut nr = 1usize;
        loop {
            let k = self.htac[ac_nr].table_len[(0xffff & self.codebuf.wrapping_shr(16)) as usize] as u32;
            let tmp_hcode = (0xffff & self.codebuf.wrapping_shr(32 - k)) as i32;
            self.skip_kbits(k);
            let min = self.htac[ac_nr].minor_code[k as usize];
            let byte_temp = self.htac[ac_nr].v[word_hi_lo(k, (0xff & (tmp_hcode - min)) as u32) as usize] as u32;
            let size_val = byte_temp & 15;
            let count_0 = byte_temp >> 4;
            if size_val == 0 {
                if count_0 != 15 { break; }
                nr += 16;
            } else {
                nr += count_0 as usize;
                if nr >= tables::DEZIGZAG.len() { break; }
                let idx = tables::DEZIGZAG[nr] as usize;
                nr += 1;
                self.dct_coeff[position + idx] = self.get_kbits(size_val);
            }
            if nr >= 64 { break; }
        }
    }

    fn idct(&mut self, index: usize, nblock: usize) {
        const F1: i32 = 277;   // 1.082392200
        const F2: i32 = 362;   // 1.414213562
        const F3: i32 = 473;   // 1.847759065
        const F4: i32 = 669;   // 2.613125930
        let mul = |v: i32, c: i32| (v * c) >> 8;
        let q = self.mqt[nblock];
        let inp = self.dct_coeff;
        let mut ws = [0i64; 64];
        // pass 1: columns (dequant in i64)
        for ctr in 0..8 {
            let c = index + ctr;
            if (inp[c + 8] | inp[c + 16] | inp[c + 24] | inp[c + 32] | inp[c + 40] | inp[c + 48] | inp[c + 56]) == 0 {
                let dcval = (inp[c] as i64 * q[ctr]) >> 16;
                for r in 0..8 { ws[ctr + r * 8] = dcval; }
                continue;
            }
            let dq = |coef: i32, qv: i64| ((coef as i64 * qv) >> 16) as i32;
            let tmp0 = dq(inp[c], q[ctr]);
            let tmp1 = dq(inp[c + 16], q[ctr + 16]);
            let tmp2 = dq(inp[c + 32], q[ctr + 32]);
            let tmp3 = dq(inp[c + 48], q[ctr + 48]);
            let tmp10 = tmp0 + tmp2;
            let tmp11 = tmp0 - tmp2;
            let tmp13 = tmp1 + tmp3;
            let tmp12 = mul(tmp1 - tmp3, F2) - tmp13;
            let a0 = tmp10 + tmp13;
            let a3 = tmp10 - tmp13;
            let a1 = tmp11 + tmp12;
            let a2 = tmp11 - tmp12;
            let tmp4 = dq(inp[c + 8], q[ctr + 8]);
            let tmp5 = dq(inp[c + 24], q[ctr + 24]);
            let tmp6 = dq(inp[c + 40], q[ctr + 40]);
            let tmp7 = dq(inp[c + 56], q[ctr + 56]);
            let z13 = tmp6 + tmp5;
            let z10 = tmp6 - tmp5;
            let z11 = tmp4 + tmp7;
            let z12 = tmp4 - tmp7;
            let b7 = z11 + z13;
            let b11 = mul(z11 - z13, F2);
            let z5 = mul(z10 + z12, F3);
            let b10 = mul(z12, F1) - z5;
            let b12 = mul(z10, -F4) + z5;
            let b6 = b12 - b7;
            let b5 = b11 - b6;
            let b4 = b10 + b5;
            ws[ctr] = (a0 + b7) as i64;
            ws[ctr + 56] = (a0 - b7) as i64;
            ws[ctr + 8] = (a1 + b6) as i64;
            ws[ctr + 48] = (a1 - b6) as i64;
            ws[ctr + 16] = (a2 + b5) as i64;
            ws[ctr + 40] = (a2 - b5) as i64;
            ws[ctr + 32] = (a3 + b4) as i64;
            ws[ctr + 24] = (a3 - b4) as i64;
        }
        // pass 2: rows -> tile_yuv via range-limit table (level shift baked in)
        for ctr in 0..8 {
            let o = ctr * 8;
            let w = |i: usize| ws[o + i] as i32;
            let tmp10 = w(0) + w(4);
            let tmp11 = w(0) - w(4);
            let tmp13 = w(2) + w(6);
            let tmp12 = mul(w(2) - w(6), F2) - tmp13;
            let a0 = tmp10 + tmp13;
            let a3 = tmp10 - tmp13;
            let a1 = tmp11 + tmp12;
            let a2 = tmp11 - tmp12;
            let z13 = w(5) + w(3);
            let z10 = w(5) - w(3);
            let z11 = w(1) + w(7);
            let z12 = w(1) - w(7);
            let b7 = z11 + z13;
            let b11 = mul(z11 - z13, F2);
            let z5 = mul(z10 + z12, F3);
            let b10 = mul(z12, F1) - z5;
            let b12 = mul(z10, -F4) + z5;
            let b6 = b12 - b7;
            let b5 = b11 - b6;
            let b4 = b10 + b5;
            let base = index + o;
            let mut put = |off: usize, val: i32| {
                let ri = ((384 + (val >> 3)) & 1023) as usize;
                self.tile_yuv[base + off] = self.rlimit[ri];
            };
            put(0, a0 + b7);
            put(7, a0 - b7);
            put(1, a1 + b6);
            put(6, a1 - b6);
            put(2, a2 + b5);
            put(5, a2 - b5);
            put(4, a3 + b4);
            put(3, a3 - b4);
        }
    }

    fn yuv_to_rgb(&mut self, txb: usize, tyb: usize) {
        let w = self.width;
        if !self.mode420 {
            let x0 = txb << 3;
            // Clip the block at the right edge rather than let it run onto the
            // next row, as both vendor decoders do.
            let cols = w.saturating_sub(x0).min(8);
            self.mark(x0, tyb << 3, 8, 8);
            let mut pos = (tyb << 3) * w + x0;
            for j in 0..8 {
                for i in 0..cols {
                    let m = (j << 3) + i;
                    let y = self.tile_yuv[m] as usize & 0xff;
                    let (cb, cr) = if self.grey { (128, 128) }
                        else { (self.tile_yuv[64 + m] as usize & 0xff, self.tile_yuv[128 + m] as usize & 0xff) };
                    if let Some(p) = self.prev_yuv.get_mut((pos + i) * 3..(pos + i) * 3 + 3) {
                        p.copy_from_slice(&[y as u8, cb as u8, cr as u8]);
                    }
                    self.put_pixel(pos + i, y, cb, cr);
                }
                pos += w;
            }
        } else {
            let x0 = txb << 4;
            // Clip at the right edge too. Unclipped, a block in the last
            // column of a width that is not a multiple of 16 ran onto the
            // start of the next rows, outside the tiles it marks. noVNC never
            // shows that overrun: it rounds its own buffer's width up to the
            // block size, so the extra columns land off screen.
            let cols = w.saturating_sub(x0).min(16);
            self.mark(x0, tyb << 4, 16, 16);
            let mut pos = (tyb << 4) * w + x0;
            for j in 0..16 {
                for i in 0..cols {
                    let blk = (j >> 3) * 2 + (i >> 3);
                    let within = ((j & 7) << 3) + (i & 7);
                    let y = self.tile_yuv[blk * 64 + within] as usize & 0xff;
                    let (cb, cr) = if self.grey { (128, 128) } else {
                        let m = ((j >> 1) << 3) + (i >> 1);
                        (self.tile_yuv[256 + m] as usize & 0xff, self.tile_yuv[320 + m] as usize & 0xff)
                    };
                    self.put_pixel(pos + i, y, cb, cr);
                }
                pos += w;
            }
        }
    }

    #[inline]
    fn put_pixel(&mut self, n: usize, y: usize, cb: usize, cr: usize) {
        if n >= self.framebuffer.len() { return; }
        let yy = self.m_y[y];
        let r = self.rlimit[clampi(256 + yy + self.cr_to_r[cr])] as u32;
        let g = self.rlimit[clampi(256 + yy + self.cb_to_g[cb] + self.cr_to_g[cr])] as u32;
        let b = self.rlimit[clampi(256 + yy + self.cb_to_b[cb])] as u32;
        self.framebuffer[n] = (r << 16) | (g << 8) | b;
    }

    fn decompress(&mut self) {
        for i in 0..384 {
            self.tile_yuv[i] = 0;
            self.tile_yuv[i + 384] = 0;
            self.dct_coeff[i] = 0;
        }
        let mut pi = 0usize;
        self.process_huffman_data_unit(0, 0, self.dc_y, pi); self.dc_y = self.previous_dc; pi += 64;
        if self.mode420 {
            self.process_huffman_data_unit(0, 0, self.dc_y, pi); self.dc_y = self.previous_dc; pi += 64;
            self.process_huffman_data_unit(0, 0, self.dc_y, pi); self.dc_y = self.previous_dc; pi += 64;
            self.process_huffman_data_unit(0, 0, self.dc_y, pi); self.dc_y = self.previous_dc; pi += 64;
            self.process_huffman_data_unit(1, 1, self.dc_cb, pi); self.dc_cb = self.previous_dc; pi += 64;
            self.process_huffman_data_unit(1, 1, self.dc_cr, pi); self.dc_cr = self.previous_dc;
        } else {
            self.process_huffman_data_unit(1, 1, self.dc_cb, pi); self.dc_cb = self.previous_dc; pi += 64;
            self.process_huffman_data_unit(1, 1, self.dc_cr, pi); self.dc_cr = self.previous_dc;
        }
        let mut pi = 0usize;
        self.idct(pi, 0); pi += 64;
        if self.mode420 {
            self.idct(pi, 0); pi += 64;
            self.idct(pi, 0); pi += 64;
            self.idct(pi, 0); pi += 64;
            self.idct(pi, 1); pi += 64;
            self.idct(pi, 1);
        } else {
            self.idct(pi, 1); pi += 64;
            self.idct(pi, 1);
        }
        self.yuv_to_rgb(self.txb, self.tyb);
    }

    /// A pass-2 block: always 4:4:4 (Y, Cb, Cr), decoded with the pass-2
    /// tables, and added to what pass 1 left in `prev_yuv` rather than drawn
    /// over it. `prev_yuv` itself is not updated — a refinement refines the
    /// pass-1 picture, as in both vendor decoders.
    fn decompress_pass2(&mut self) {
        for i in 0..384 {
            self.tile_yuv[i] = 0;
            self.tile_yuv[i + 384] = 0;
            self.dct_coeff[i] = 0;
        }
        self.process_huffman_data_unit(0, 0, self.dc_y, 0); self.dc_y = self.previous_dc;
        self.process_huffman_data_unit(1, 1, self.dc_cb, 64); self.dc_cb = self.previous_dc;
        self.process_huffman_data_unit(1, 1, self.dc_cr, 128); self.dc_cr = self.previous_dc;
        self.idct(0, 2);
        self.idct(64, 3);
        self.idct(128, 3);
        if self.mode420 {
            return; // pass 2 only exists in 4:4:4; the vendors log and ignore it
        }
        let w = self.width;
        let x0 = self.txb << 3;
        let cols = w.saturating_sub(x0).min(8);
        self.mark(x0, self.tyb << 3, 8, 8);
        let mut pos = (self.tyb << 3) * w + x0;
        for j in 0..8 {
            for i in 0..cols {
                let m = (j << 3) + i;
                let Some(p) = self.prev_yuv.get((pos + i) * 3..(pos + i) * 3 + 3) else { continue };
                let add = |base: u8, v: i32| (base as i32 + ((v & 0xff) - 128)).clamp(0, 255) as usize;
                let y = add(p[0], self.tile_yuv[m]);
                let cb = add(p[1], self.tile_yuv[64 + m]);
                let cr = add(p[2], self.tile_yuv[128 + m]);
                self.put_pixel(pos + i, y, cb, cr);
            }
            pos += w;
        }
    }

    fn move_block_index(&mut self) {
        let div = if self.mode420 { 16 } else { 8 };
        self.txb += 1;
        if self.txb >= self.tmp_w / div {
            self.tyb += 1;
            if self.tyb >= self.tmp_h / div { self.tyb = 0; }
            self.txb = 0;
        }
    }

    fn vq_color_update(&mut self, count: usize) {
        for i in 0..count {
            self.vq.index[i] = (self.codebuf.wrapping_shr(29) & VQ_INDEX_MASK) as usize;
            if (self.codebuf.wrapping_shr(31) & VQ_HEADER_MASK) == 0 {
                self.updatereadbuf(3);
            } else {
                self.vq.color[self.vq.index[i]] = self.codebuf.wrapping_shr(5) & VQ_COLOR_MASK;
                self.updatereadbuf(27);
            }
        }
    }

    fn vq_decompress(&mut self) {
        for i in 0..384 { self.tile_yuv[i] = 0; }
        if self.vq.bitmap_bits == 0 {
            let color = self.vq.color[self.vq.index[0]];
            for p in 0..64 {
                self.tile_yuv[p] = ((color & 0xff0000) >> 16) as i32;
                self.tile_yuv[p + 64] = ((color & 0x00ff00) >> 8) as i32;
                self.tile_yuv[p + 128] = (color & 0x0000ff) as i32;
            }
        } else {
            for p in 0..64 {
                let data = (0xffff & self.codebuf.wrapping_shr(32 - self.vq.bitmap_bits)) as usize;
                let ci = self.vq.index[data & 3];
                let color = self.vq.color[ci];
                self.tile_yuv[p] = ((color & 0xff0000) >> 16) as i32;
                self.tile_yuv[p + 64] = ((color & 0x00ff00) >> 8) as i32;
                self.tile_yuv[p + 128] = (color & 0x0000ff) as i32;
                self.skip_kbits(self.vq.bitmap_bits);
            }
        }
        let saved = self.mode420;
        self.mode420 = false;
        self.yuv_to_rgb(self.txb, self.tyb);
        self.mode420 = saved;
    }

    /// Decode an AST2300 frame whose header names a luma and a chroma table
    /// (Avocent's does). Pass-2 blocks, if any, reuse the same two.
    pub fn decode_ast2300(&mut self, w: usize, h: usize, mode420: bool, y_sel: usize, uv_sel: usize, comp: &[u8]) {
        self.decode_ast2300_with(w, h, mode420, [(y_sel, false), (uv_sel, true), (y_sel, false), (uv_sel, true)], comp);
    }

    /// Decode an AMI AST2300 frame (Quanta JViewer, SP-X H5Viewer): the raw
    /// compressed bitstream, already stripped of its 86-byte video header.
    ///
    /// The header's table fields mean what the vendor decoders take them to:
    /// `selector` (byte 44) sets both pass-1 tables, `advance` (byte 47) both
    /// pass-2 tables, and `mapping` (byte 45) swaps the chroma tables for the
    /// luma ones at the same level. The first port read 44 as luma and 47 as
    /// chroma, which is only right when they are equal — the X570D4U's are not.
    pub fn decode_ami_frame(&mut self, w: usize, h: usize, mode420: bool,
                            selector: usize, advance: usize, mapping: bool, comp: &[u8]) {
        let uv = !mapping;
        self.decode_ast2300_with(w, h, mode420,
            [(selector, false), (selector, uv), (advance, false), (advance, uv)], comp);
    }

    /// `tables`: (selector, from the chroma set?) for pass-1 luma, pass-1
    /// chroma, pass-2 luma and pass-2 chroma.
    fn decode_ast2300_with(&mut self, w: usize, h: usize, mode420: bool,
                           tables: [(usize, bool); 4], comp: &[u8]) {
        self.frames += 1;
        self.bytes_in += comp.len() as u64;
        if self.width != w || self.height != h || self.framebuffer.len() != w * h {
            self.resize(w, h);
        }
        self.buffer = comp.to_vec();
        self.y_sel = tables[0].0; self.uv_sel = tables[1].0; self.mode420 = mode420;
        let mb = if self.mode420 { 16 } else { 8 };
        self.tmp_w = if w % mb == 0 { w } else { w + mb - w % mb };
        self.tmp_h = if h % mb == 0 { h } else { h + mb - h % mb };
        for (dst, (sel, chroma)) in tables.into_iter().enumerate() {
            self.load_quant_into(dst, sel, chroma);
        }
        self.old_y_sel = self.y_sel as i32;
        self.vq.index = [0, 1, 2, 3];
        self.vq.color = [32896, 16744576, 8421504, 12615808];
        self.decode_loop_from(0);
    }

    pub fn decode_rect(&mut self, x: usize, y: usize, w: usize, h: usize, encoding: u32, _mode: u32, data: &[u8]) {
        self.frames += 1;
        self.bytes_in += data.len() as u64;
        match encoding {
            0x57 => {                       // AST2100 (X10/X11)
                if data.len() < 4 { return; }
                self.set_options(w, h, data);
                self.decode_loop();
            }
            0x59 => self.decode_raw555(x, y, w, h, data),  // X9 full frame, raw RGB555
            0x00 => self.decode_delta555(data),            // X9 tile delta
            _ => {}
        }
    }

    /// X9 delta (encoding 0): a 10-byte frame header `[u32=0][u16 ntiles][u32 len]`
    /// then `ntiles` records of `[u32=0][u8 row][u8 col]` + a 16x16 RGB555 tile.
    /// Each tile is blitted at (col*16, row*16) onto the persistent framebuffer.
    fn decode_delta555(&mut self, data: &[u8]) {
        if data.len() < 10 { return; }
        let ntiles = u16::from_be_bytes([data[4], data[5]]) as usize;
        const TILE: usize = 16;
        const REC: usize = 6 + TILE * TILE * 2; // 6 header + 512 pixels = 518
        let mut off = 10;
        for _ in 0..ntiles {
            if off + REC > data.len() { break; }
            let row = data[off + 4] as usize;
            let col = data[off + 5] as usize;
            let px = &data[off + 6..off + 6 + TILE * TILE * 2];
            let ox = col * TILE;
            let oy = row * TILE;
            self.mark(ox, oy, TILE, TILE);
            for r in 0..TILE {
                let fy = oy + r;
                if fy >= self.height { break; }
                for c in 0..TILE {
                    let fx = ox + c;
                    if fx >= self.width { continue; }
                    let i = (r * TILE + c) * 2;
                    let v = px[i] as u16 | ((px[i + 1] as u16) << 8);
                    let (rr, gg, bb) = rgb555(v);
                    self.framebuffer[fy * self.width + fx] = (rr << 16) | (gg << 8) | bb;
                }
            }
            off += REC;
        }
    }

    /// X9 sends full/partial rects as raw little-endian RGB555, preceded by a
    /// short header (its size = data.len() - w*h*2). Blit into the framebuffer.
    fn decode_raw555(&mut self, x: usize, y: usize, w: usize, h: usize, data: &[u8]) {
        let need = w * h * 2;
        if data.len() < need { return; }
        let px = &data[data.len() - need..];   // skip the leading header
        if self.width == 0 || self.framebuffer.len() != self.width * self.height { return; }
        self.mark(x, y, w, h);
        for row in 0..h {
            let fy = y + row;
            if fy >= self.height { break; }
            for col in 0..w {
                let fx = x + col;
                if fx >= self.width { continue; }
                let i = (row * w + col) * 2;
                let v = px[i] as u16 | ((px[i + 1] as u16) << 8);
                let (r, g, b) = rgb555(v);
                self.framebuffer[fy * self.width + fx] = (r << 16) | (g << 8) | b;
            }
        }
    }

    fn set_options(&mut self, w: usize, h: usize, data: &[u8]) {
        let mode = (data[2] as usize) * 256 + data[3] as usize;
        self.buffer = data.to_vec();
        if self.width != w || self.height != h || self.framebuffer.len() != w * h {
            self.width = w;
            self.height = h;
            self.framebuffer = vec![0; w * h];
            self.new_geometry();
        }
        if mode == 444 {
            self.y_sel = 7; self.uv_sel = 7; self.mode420 = false;
        } else {
            self.y_sel = 4; self.uv_sel = 7; self.mode420 = true;
        }
        let mb = if self.mode420 { 16 } else { 8 };
        self.tmp_w = if w % mb == 0 { w } else { w + mb - w % mb };
        self.tmp_h = if h % mb == 0 { h } else { h + mb - h % mb };
        if self.old_y_sel != self.y_sel as i32 {
            self.load_quant(false);
            self.load_quant(true);
            self.old_y_sel = self.y_sel as i32;
        }
        self.vq.index = [0, 1, 2, 3];
        self.vq.color = [32896, 16744576, 8421504, 12615808];
    }

    fn decode_loop(&mut self) { self.decode_loop_from(4); }

    fn decode_loop_from(&mut self, start: usize) {
        self.index = start;
        self.codebuf = self.get_qbytes(4);
        self.newbuf = self.get_qbytes(4);
        self.txb = 0; self.tyb = 0;
        self.newbits = 32;
        self.dc_y = 0; self.dc_cb = 0; self.dc_cr = 0;
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > 4_000_000 { break; }
            let code = self.codebuf.wrapping_shr(28) & 0xf;
            match code {
                JPEG_NO_SKIP_CODE => { self.updatereadbuf(4); self.decompress(); self.move_block_index(); }
                FRAME_END_CODE => break,
                JPEG_SKIP_CODE => {
                    self.txb = ((self.codebuf & 0x0FF0_0000) >> 20) as usize;
                    self.tyb = ((self.codebuf & 0x000F_F000) >> 12) as usize;
                    self.updatereadbuf(20);
                    self.decompress();
                    self.move_block_index();
                }
                JPEG_NO_SKIP_PASS2_CODE => { self.updatereadbuf(4); self.decompress_pass2(); self.move_block_index(); }
                JPEG_SKIP_PASS2_CODE => {
                    self.txb = ((self.codebuf & 0x0FF0_0000) >> 20) as usize;
                    self.tyb = ((self.codebuf & 0x000F_F000) >> 12) as usize;
                    self.updatereadbuf(20);
                    self.decompress_pass2();
                    self.move_block_index();
                }
                VQ_NO_SKIP_1 => { self.updatereadbuf(4); self.vq.bitmap_bits = 0; self.vq_color_update(1); self.vq_decompress(); self.move_block_index(); }
                VQ_SKIP_1 => { self.vq_skip(); self.vq.bitmap_bits = 0; self.vq_color_update(1); self.vq_decompress(); self.move_block_index(); }
                VQ_NO_SKIP_2 => { self.updatereadbuf(4); self.vq.bitmap_bits = 1; self.vq_color_update(2); self.vq_decompress(); self.move_block_index(); }
                VQ_SKIP_2 => { self.vq_skip(); self.vq.bitmap_bits = 1; self.vq_color_update(2); self.vq_decompress(); self.move_block_index(); }
                VQ_NO_SKIP_4 => { self.updatereadbuf(4); self.vq.bitmap_bits = 2; self.vq_color_update(4); self.vq_decompress(); self.move_block_index(); }
                VQ_SKIP_4 => { self.vq_skip(); self.vq.bitmap_bits = 2; self.vq_color_update(4); self.vq_decompress(); self.move_block_index(); }
                _ => break,
            }
            if self.index >= self.buffer.len() && self.newbits <= 0 { break; }
        }
    }

    fn vq_skip(&mut self) {
        self.txb = ((self.codebuf & 0x0FF0_0000) >> 20) as usize;
        self.tyb = ((self.codebuf & 0x000F_F000) >> 12) as usize;
        self.updatereadbuf(20);
    }
}

#[inline]
fn clampi(i: i32) -> usize {
    if i < 0 { 0 } else if i > 1407 { 1407 } else { i as usize }
}

#[cfg(test)]
mod damage_tests {
    use super::*;
    use crate::damage::Rect;

    /// An AST2100 frame (encoding 0x57) of `mode` that ends at once: the
    /// first code in the stream, the top nibble of a little-endian word, is
    /// FRAME_END.
    fn empty_frame(mode: u16) -> Vec<u8> {
        let m = mode.to_be_bytes();
        vec![0, 0, m[0], m[1], 0, 0, 0, (FRAME_END_CODE as u8) << 4, 0, 0, 0, 0]
    }

    #[test]
    fn take_dirty_clears() {
        let mut d = Decoder::new(64, 64);
        // A new decoder is all news.
        let first = d.take_dirty().unwrap();
        assert!(first.full && first.resized);
        assert_eq!(d.take_dirty(), None);
        d.mark(40, 40, 1, 1);
        assert_eq!(d.take_dirty().unwrap().rects, vec![Rect { x: 32, y: 32, w: 32, h: 32 }]);
        assert_eq!(d.take_dirty(), None);
    }

    #[test]
    fn resize_marks_everything_and_flags_it() {
        let mut d = Decoder::new(64, 64);
        d.take_dirty();
        d.resize(100, 50);
        let dmg = d.take_dirty().unwrap();
        assert!(dmg.full && dmg.resized);
        assert_eq!(dmg.rects, vec![Rect { x: 0, y: 0, w: 100, h: 50 }]);
        assert_eq!(d.take_dirty(), None);
    }

    #[test]
    fn set_options_same_geometry_marks_nothing() {
        let mut d = Decoder::new(64, 48);
        d.take_dirty();
        d.decode_rect(0, 0, 64, 48, 0x57, 0, &empty_frame(420));
        assert_eq!(d.take_dirty(), None);
        // A mode change at the same size reallocates nothing either.
        d.decode_rect(0, 0, 64, 48, 0x57, 0, &empty_frame(444));
        assert_eq!(d.take_dirty(), None);
    }

    #[test]
    fn set_options_new_geometry_marks_all() {
        let mut d = Decoder::new(64, 48);
        d.take_dirty();
        d.decode_rect(0, 0, 80, 40, 0x57, 0, &empty_frame(420));
        let dmg = d.take_dirty().unwrap();
        assert!(dmg.full && dmg.resized);
        assert_eq!((d.width, d.height), (80, 40));
    }

    #[test]
    fn x9_raw_rect_marks_its_tiles() {
        let mut d = Decoder::new(100, 100);
        d.take_dirty();
        // 2x2 raw RGB555 at (40, 70) behind a 4-byte header.
        let mut data = vec![0u8; 4];
        data.extend_from_slice(&[0x5a, 0x2d].repeat(4));
        d.decode_rect(40, 70, 2, 2, 0x59, 0, &data);
        assert_eq!(d.take_dirty().unwrap().rects, vec![Rect { x: 32, y: 64, w: 32, h: 32 }]);
    }

    /// X9's encodings as `rfb.rs` receives them: raw RGB555 rectangles
    /// (0x59) behind a header, and tile deltas (0) of 16x16 RGB555 tiles at
    /// row/column positions; then an AST2100 frame (0x57) that changes mode.
    #[test]
    fn x9_streams_replay() {
        use crate::damage::tests::Replay;
        let rgb555 = |n: usize, seed: u16| -> Vec<u8> {
            (0..n).flat_map(|i| ((i as u16).wrapping_mul(97).wrapping_add(seed) & 0x7FFF).to_le_bytes()).collect()
        };
        let mut d = Decoder::new(100, 80);
        let mut rp = Replay::default();
        rp.step(&mut d, "new");
        for (i, (x, y, w, h)) in [(10, 10, 20, 15), (90, 70, 10, 10), (0, 0, 1, 1)].into_iter().enumerate() {
            let mut data = vec![0u8; 6];
            data.extend(rgb555(w * h, i as u16 * 1000));
            d.decode_rect(x, y, w, h, 0x59, 0, &data);
            assert!(!rp.step(&mut d, &format!("raw {i}")).unwrap().full);
        }
        // Two delta tiles, one clipped by the right and bottom edges.
        let mut delta = vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        for (row, col) in [(1u8, 2u8), (4, 6)] {
            delta.extend_from_slice(&[0, 0, 0, 0, row, col]);
            delta.extend(rgb555(256, u16::from(row) * 7));
        }
        d.decode_rect(0, 0, 100, 80, 0x00, 0, &delta);
        assert!(!rp.step(&mut d, "delta").unwrap().full);
        // A delta with no tiles is no damage.
        d.decode_rect(0, 0, 100, 80, 0x00, 0, &[0; 10]);
        assert_eq!(rp.step(&mut d, "static"), None);
        // The mode changes to a new geometry.
        d.decode_rect(0, 0, 120, 90, 0x57, 0, &empty_frame(444));
        assert!(rp.step(&mut d, "mode change").unwrap().resized);
    }

    #[test]
    fn write_diff_marks_only_what_differs() {
        let mut d = Decoder::new(70, 40);
        d.take_dirty();
        let mut next = d.framebuffer.clone();
        next[39 * 70 + 69] = 0x123456;
        d.write_diff(&next);
        assert_eq!(d.framebuffer, next);
        assert_eq!(d.take_dirty().unwrap().rects, vec![Rect { x: 64, y: 32, w: 6, h: 8 }]);
        d.write_diff(&next);
        assert_eq!(d.take_dirty(), None);
    }

    /// An AST2100/AST2300 bitstream: bits are written most significant
    /// first into 32-bit words, which the decoder reads little-endian.
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl Bits {
        fn put(&mut self, v: u32, bits: u32) -> &mut Self {
            for i in (0..bits).rev() {
                self.acc = (self.acc << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 32 {
                    self.out.extend(self.acc.to_le_bytes());
                    (self.acc, self.n) = (0, 0);
                }
            }
            self
        }

        fn finish(&mut self) -> Vec<u8> {
            self.put(FRAME_END_CODE, 4);
            while self.n != 0 {
                self.put(0, 1);
            }
            self.out.extend([0; 8]);
            std::mem::take(&mut self.out)
        }

        /// A DC difference: its category's code from the standard table
        /// (JPEG Annex K), then the value in that many bits, negatives as
        /// JPEG writes them.
        fn dc(&mut self, chroma: bool, v: i32) -> &mut Self {
            let cat = 32 - v.unsigned_abs().leading_zeros();
            let (code, len) = match (chroma, cat) {
                (false, 0) => (0b00, 2),
                (false, c) => (c + 1, 3), // categories 1-5: 010..110
                (true, c @ 0..=2) => (c, 2),
                (true, 3) => (0b110, 3),
                _ => unreachable!("keep test DCs small"),
            };
            self.put(code, len);
            if cat > 0 {
                self.put(if v > 0 { v as u32 } else { (v + (1 << cat) - 1) as u32 }, cat);
            }
            self
        }

        /// A luma block: the DC, one AC coefficient of +1 (code 00, run 0,
        /// size 1) so it is not flat, and end of block (1010).
        fn y(&mut self, dc: i32) -> &mut Self {
            self.dc(false, dc).put(0b00, 2).put(1, 1).put(0b1010, 4)
        }

        /// A chroma block: the DC, then end of block (00).
        fn c(&mut self, dc: i32) -> &mut Self {
            self.dc(true, dc).put(0b00, 2)
        }

        fn skip_to(&mut self, code: u32, txb: u32, tyb: u32) -> &mut Self {
            self.put(code, 4).put(txb, 8).put(tyb, 8)
        }

        fn jpeg420(&mut self, dc: i32) -> &mut Self {
            self.y(dc).y(-dc).y(dc).y(1).c(-2).c(3)
        }

        fn jpeg444(&mut self, dc: i32) -> &mut Self {
            self.y(dc).c(2).c(-3)
        }

        /// A VQ colour update: a new YCbCr colour into slot `i`, or (None)
        /// just the slot.
        fn vq(&mut self, i: u32, color: Option<u32>) -> &mut Self {
            match color {
                Some(c) => self.put(1, 1).put(i, 2).put(c, 24),
                None => self.put(0, 1).put(i, 2),
            }
        }
    }

    /// Real AST2100/AST2300 block streams, through both entry points, at a
    /// size that is a multiple of neither block size, so the right-edge and
    /// bottom-edge blocks are clipped: 4:2:0 and 4:4:4 JPEG blocks, VQ with
    /// one, two and four colours, and pass-2 refinements. The replay checks
    /// every pixel each step writes was marked.
    #[test]
    fn block_codec_replay() {
        use crate::damage::tests::Replay;
        let (w, h) = (100, 52);
        let frame = |mode: u16, bits: &mut Bits| -> Vec<u8> {
            let mut v = mode.to_be_bytes().to_vec();
            v.splice(0..0, [0, 0]);
            v.extend(bits.finish());
            v
        };
        let mut d = Decoder::new(w, h);
        let mut rp = Replay::default();
        rp.step(&mut d, "new");
        let mut step = |d: &mut Decoder, what: &str, decode: &dyn Fn(&mut Decoder)| {
            let before = d.framebuffer.clone();
            decode(d);
            assert_ne!(d.framebuffer, before, "{what}: drew nothing");
            let dmg = rp.step(d, what).expect(what);
            assert!(!dmg.full && !dmg.resized, "{what}: {dmg:?}");
        };

        // 4:2:0, a lone block in the last column (x 96..111 of 100).
        let f = frame(420, Bits::default().skip_to(JPEG_SKIP_CODE, 6, 0).jpeg420(15));
        step(&mut d, "420 right edge", &|d| d.decode_rect(0, 0, w, h, 0x57, 0, &f));
        assert_ne!(d.framebuffer[96], 0, "the right-edge block was not drawn");
        assert_eq!(d.framebuffer[w], 0, "the right-edge block ran onto the next row");

        // 4:2:0 in sequence, then VQ (drawn as one 8x8 block) and the
        // bottom-right block, clipped both ways.
        let f = frame(420, Bits::default()
            .put(JPEG_NO_SKIP_CODE, 4).jpeg420(-7)
            .put(VQ_NO_SKIP_1, 4).vq(2, Some(0x50_A0_30))
            .skip_to(JPEG_SKIP_CODE, 6, 3).jpeg420(5));
        step(&mut d, "420 sequence", &|d| d.decode_rect(0, 0, w, h, 0x57, 0, &f));

        // 4:4:4 at the same size: a clipped corner block, then two- and
        // four-colour VQ blocks with bitmaps.
        let mut b = Bits::default();
        b.skip_to(JPEG_SKIP_CODE, 12, 6).jpeg444(12);
        b.skip_to(VQ_SKIP_2, 0, 6).vq(0, Some(0xE0_80_80)).vq(1, Some(0x20_60_C0));
        for p in 0..64 {
            b.put((p ^ (p >> 3)) & 1, 1);
        }
        b.put(VQ_NO_SKIP_4, 4).vq(0, None).vq(1, None).vq(2, Some(0x80_20_E0)).vq(3, Some(0x40_C0_40));
        for p in 0..64 {
            b.put(p % 4, 2);
        }
        let f = frame(444, &mut b);
        step(&mut d, "444 and vq", &|d| d.decode_rect(0, 0, w, h, 0x57, 0, &f));
        // The two-colour bitmap alternates, so the stream stayed in step.
        assert_ne!(d.framebuffer[48 * w], d.framebuffer[48 * w + 1], "the VQ bitmap was not drawn");

        // Pass 2 refines what pass 1 left: the clipped corner, then the next
        // block in order, which wraps to (0, 0).
        let f = frame(444, Bits::default()
            .skip_to(JPEG_SKIP_PASS2_CODE, 12, 6).jpeg444(9)
            .put(JPEG_NO_SKIP_PASS2_CODE, 4).jpeg444(-6));
        step(&mut d, "pass 2", &|d| d.decode_rect(0, 0, w, h, 0x57, 0, &f));

        // The AST2300 entry points (Avocent's and AMI's), which carry no
        // 4-byte header.
        let f = Bits::default().skip_to(JPEG_SKIP_CODE, 6, 3).jpeg420(-11).finish();
        step(&mut d, "ast2300", &|d| d.decode_ast2300(w, h, true, 4, 7, &f));
        let f = Bits::default().skip_to(JPEG_SKIP_CODE, 12, 0).jpeg444(14)
            .skip_to(JPEG_SKIP_PASS2_CODE, 12, 0).jpeg444(4).finish();
        step(&mut d, "ami 444", &|d| d.decode_ami_frame(w, h, false, 4, 5, true, &f));
        assert_eq!(rp.partial, 6);
    }
}
