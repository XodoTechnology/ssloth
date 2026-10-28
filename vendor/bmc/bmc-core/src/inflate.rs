//! Raw DEFLATE (RFC 1951), enough to read what BMCs send.
//!
//! Carried rather than taken as a dependency: it is needed for the gzip that
//! iDRAC insists on for its JSON endpoints, the PNG of its console preview and
//! the pack200 viewer an ATEN BMC serves, and all are one-shot decodes.

/// Minimal gzip reader: skip the header, then raw-inflate the deflate stream.
/// Anything that is not gzip comes back unchanged.
pub fn gunzip(data: &[u8]) -> Vec<u8> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return data.to_vec();
    }
    let flg = data[3];
    let mut i = 10;
    if flg & 0x04 != 0 {
        // FEXTRA
        if i + 2 > data.len() {
            return Vec::new();
        }
        let n = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        i += 2 + n;
    }
    for bit in [0x08u8, 0x10] {
        // FNAME, FCOMMENT: NUL-terminated
        if flg & bit != 0 {
            while i < data.len() && data[i] != 0 {
                i += 1;
            }
            i += 1;
        }
    }
    if flg & 0x02 != 0 {
        i += 2; // FHCRC
    }
    if i >= data.len() {
        return Vec::new();
    }
    crate::inflate::inflate(&data[i..])
}

/// Raw DEFLATE (RFC 1951). Small enough to carry rather than take a dependency.
pub fn inflate(src: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let (mut pos, mut bit) = (0usize, 0u32);
    let getbit = |src: &[u8], pos: &mut usize, bit: &mut u32| -> u32 {
        if *pos >= src.len() {
            return 0;
        }
        let v = (src[*pos] >> *bit) as u32 & 1;
        *bit += 1;
        if *bit == 8 {
            *bit = 0;
            *pos += 1;
        }
        v
    };
    let getbits = |src: &[u8], pos: &mut usize, bit: &mut u32, n: u32| -> u32 {
        let mut v = 0;
        for k in 0..n {
            v |= getbit(src, pos, bit) << k;
        }
        v
    };
    loop {
        if pos >= src.len() {
            break;
        }
        let final_block = getbit(src, &mut pos, &mut bit);
        let btype = getbits(src, &mut pos, &mut bit, 2);
        match btype {
            0 => {
                if bit != 0 {
                    bit = 0;
                    pos += 1;
                }
                if pos + 4 > src.len() {
                    break;
                }
                let len = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
                pos += 4;
                if pos + len > src.len() {
                    break;
                }
                out.extend_from_slice(&src[pos..pos + len]);
                pos += len;
            }
            1 | 2 => {
                let (lit, dist) = if btype == 1 {
                    (fixed_lit(), fixed_dist())
                } else {
                    match dynamic_tables(src, &mut pos, &mut bit) {
                        Some(t) => t,
                        None => break,
                    }
                };
                if !inflate_block(src, &mut pos, &mut bit, &lit, &dist, &mut out) {
                    break;
                }
            }
            _ => break,
        }
        if final_block == 1 {
            break;
        }
    }
    out
}

/// A canonical Huffman table: (code lengths) -> decode by walking bit by bit.
struct Huff {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn build_huff(lengths: &[u8]) -> Huff {
    let mut counts = [0u16; 16];
    for &l in lengths {
        counts[l as usize] += 1;
    }
    counts[0] = 0;
    let mut offs = [0u16; 16];
    for i in 1..16 {
        offs[i] = offs[i - 1] + counts[i - 1];
    }
    let mut symbols = vec![0u16; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l != 0 {
            symbols[offs[l as usize] as usize] = sym as u16;
            offs[l as usize] += 1;
        }
    }
    Huff { counts, symbols }
}

fn decode_sym(src: &[u8], pos: &mut usize, bit: &mut u32, h: &Huff) -> Option<u16> {
    let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
    for len in 1..16 {
        if *pos >= src.len() {
            return None;
        }
        let b = (src[*pos] >> *bit) as i32 & 1;
        *bit += 1;
        if *bit == 8 {
            *bit = 0;
            *pos += 1;
        }
        code |= b;
        let count = h.counts[len] as i32;
        if code - count < first {
            return h.symbols.get((index + (code - first)) as usize).copied();
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    None
}

fn fixed_lit() -> Huff {
    let mut l = vec![8u8; 288];
    l[144..256].fill(9);
    l[256..280].fill(7);
    build_huff(&l)
}

fn fixed_dist() -> Huff {
    build_huff(&vec![5u8; 30])
}

fn dynamic_tables(src: &[u8], pos: &mut usize, bit: &mut u32) -> Option<(Huff, Huff)> {
    let getbits = |pos: &mut usize, bit: &mut u32, n: u32| -> u32 {
        let mut v = 0;
        for k in 0..n {
            if *pos >= src.len() {
                return v;
            }
            v |= (((src[*pos] >> *bit) as u32) & 1) << k;
            *bit += 1;
            if *bit == 8 {
                *bit = 0;
                *pos += 1;
            }
        }
        v
    };
    let hlit = getbits(pos, bit, 5) as usize + 257;
    let hdist = getbits(pos, bit, 5) as usize + 1;
    let hclen = getbits(pos, bit, 4) as usize + 4;
    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut cl = [0u8; 19];
    for i in 0..hclen {
        cl[ORDER[i]] = getbits(pos, bit, 3) as u8;
    }
    let clh = build_huff(&cl);
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let sym = decode_sym(src, pos, bit, &clh)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                let prev = if i > 0 { lengths[i - 1] } else { 0 };
                let n = 3 + getbits(pos, bit, 2) as usize;
                for _ in 0..n {
                    if i < lengths.len() {
                        lengths[i] = prev;
                        i += 1;
                    }
                }
            }
            17 => i += 3 + getbits(pos, bit, 3) as usize,
            18 => i += 11 + getbits(pos, bit, 7) as usize,
            _ => return None,
        }
    }
    if i > lengths.len() {
        return None;
    }
    Some((build_huff(&lengths[..hlit]), build_huff(&lengths[hlit..])))
}

fn inflate_block(src: &[u8], pos: &mut usize, bit: &mut u32, lit: &Huff, dist: &Huff,
                 out: &mut Vec<u8>) -> bool {
    const LBASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51,
        59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
        5, 5, 5, 5, 0];
    const DBASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
        513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10,
        10, 11, 11, 12, 12, 13, 13];
    let getbits = |pos: &mut usize, bit: &mut u32, n: u32| -> u32 {
        let mut v = 0;
        for k in 0..n {
            if *pos >= src.len() {
                return v;
            }
            v |= (((src[*pos] >> *bit) as u32) & 1) << k;
            *bit += 1;
            if *bit == 8 {
                *bit = 0;
                *pos += 1;
            }
        }
        v
    };
    loop {
        let Some(sym) = decode_sym(src, pos, bit, lit) else { return false };
        match sym {
            256 => return true,
            0..=255 => out.push(sym as u8),
            _ => {
                let i = sym as usize - 257;
                if i >= 29 {
                    return false;
                }
                let len = LBASE[i] as usize + getbits(pos, bit, LEXT[i] as u32) as usize;
                let Some(dsym) = decode_sym(src, pos, bit, dist) else { return false };
                let d = dsym as usize;
                if d >= 30 {
                    return false;
                }
                let distance = DBASE[d] as usize + getbits(pos, bit, DEXT[d] as u32) as usize;
                if distance > out.len() || distance == 0 {
                    return false;
                }
                let start = out.len() - distance;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
        }
    }
}
