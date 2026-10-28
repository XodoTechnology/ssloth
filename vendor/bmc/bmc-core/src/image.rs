//! Readers for the console-preview images BMCs serve: PNG from iDRAC, BMP from
//! ATEN/Supermicro.
//!
//! Only the shapes those actually produce are handled, and anything else is
//! rejected rather than half-decoded — a wrong guess would show the user a
//! plausible-looking but wrong picture of their machine.

/// A decoded image, in the same 0xRRGGBB words the framebuffers use.
pub struct Image {
    pub width: usize,
    pub height: usize,
    pub rgb: Vec<u32>,
}

/// Decode whichever format the bytes turn out to be.
pub fn decode(data: &[u8]) -> Option<Image> {
    if data.starts_with(b"BM") {
        decode_bmp(data)
    } else {
        decode_png(data)
    }
}

/// Uncompressed BMP, which is what ATEN BMCs serve: bottom-up rows, 16bpp
/// RGB555 in practice, though 24- and 32-bit are handled the same way.
pub fn decode_bmp(data: &[u8]) -> Option<Image> {
    if data.len() < 54 || !data.starts_with(b"BM") {
        return None;
    }
    let u16at = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().ok().unwrap_or([0; 2]));
    let u32at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().ok().unwrap_or([0; 4]));

    let offset = u32at(10) as usize;
    let width = u32at(18) as i32;
    // A negative height means the rows are stored top-down instead.
    let raw_height = u32at(22) as i32;
    let bpp = u16at(28);
    let compression = u32at(30);

    // BI_RGB only: the compressed variants do not turn up here, and guessing at
    // a bitfield layout would silently shift every colour.
    if compression != 0 || width <= 0 || raw_height == 0 {
        return None;
    }
    let (height, bottom_up) = (raw_height.unsigned_abs() as usize, raw_height > 0);
    let width = width as usize;
    if width > 8192 || height > 8192 {
        return None;
    }
    let bytes = match bpp {
        16 => 2,
        24 => 3,
        32 => 4,
        _ => return None,
    };
    // Rows are padded out to a four-byte boundary.
    let stride = (width * bytes + 3) & !3;
    if data.len() < offset + stride * height {
        return None;
    }

    let mut rgb = vec![0u32; width * height];
    for y in 0..height {
        let src_row = if bottom_up { height - 1 - y } else { y };
        let row = offset + src_row * stride;
        for x in 0..width {
            let o = row + x * bytes;
            let px = match bpp {
                16 => {
                    // X1R5G5B5, expanded by replicating the high bits so white
                    // reaches 0xFF rather than 0xF8.
                    let v = u16::from_le_bytes([data[o], data[o + 1]]);
                    let (r, g, b) = ((v >> 10) & 0x1F, (v >> 5) & 0x1F, v & 0x1F);
                    let e = |c: u16| ((c << 3) | (c >> 2)) as u32;
                    (e(r) << 16) | (e(g) << 8) | e(b)
                }
                // BMP stores blue first.
                _ => ((data[o + 2] as u32) << 16) | ((data[o + 1] as u32) << 8) | data[o] as u32,
            };
            rgb[y * width + x] = px;
        }
    }
    Some(Image { width, height, rgb })
}

/// PNG: 8 bits per channel, greyscale/RGB/RGBA, non-interlaced.
pub fn decode_png(data: &[u8]) -> Option<Image> {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let (mut width, mut height) = (0usize, 0usize);
    let (mut depth, mut colour) = (0u8, 0u8);
    let mut idat: Vec<u8> = Vec::new();

    let mut i = 8;
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes(data[i..i + 4].try_into().ok()?) as usize;
        let kind = &data[i + 4..i + 8];
        let body = data.get(i + 8..i + 8 + len)?;
        match kind {
            b"IHDR" => {
                if len < 13 {
                    return None;
                }
                width = u32::from_be_bytes(body[0..4].try_into().ok()?) as usize;
                height = u32::from_be_bytes(body[4..8].try_into().ok()?) as usize;
                depth = body[8];
                colour = body[9];
                // Interlaced images need a different pass structure; refuse.
                if body[12] != 0 {
                    return None;
                }
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        i += 12 + len; // length + type + body + CRC
    }

    if depth != 8 || width == 0 || height == 0 || width > 8192 || height > 8192 {
        return None;
    }
    let channels = match colour {
        0 => 1, // greyscale
        2 => 3, // RGB
        6 => 4, // RGBA
        _ => return None,
    };

    // Strip the 2-byte zlib header; the trailing Adler sum is simply ignored.
    let raw = crate::inflate::inflate(idat.get(2..)?);
    let stride = width * channels;
    if raw.len() < height * (stride + 1) {
        return None;
    }

    // Undo the per-scanline filters, which are defined against the bytes of the
    // previous line, so this has to run in order.
    let mut out = vec![0u8; height * stride];
    for y in 0..height {
        let filter = raw[y * (stride + 1)];
        let src = &raw[y * (stride + 1) + 1..y * (stride + 1) + 1 + stride];
        for x in 0..stride {
            let a = if x >= channels { out[y * stride + x - channels] } else { 0 };
            let b = if y > 0 { out[(y - 1) * stride + x] } else { 0 };
            let c = if x >= channels && y > 0 {
                out[(y - 1) * stride + x - channels]
            } else {
                0
            };
            let v = src[x];
            out[y * stride + x] = match filter {
                0 => v,
                1 => v.wrapping_add(a),
                2 => v.wrapping_add(b),
                3 => v.wrapping_add((((a as u16) + (b as u16)) / 2) as u8),
                4 => v.wrapping_add(paeth(a, b, c)),
                _ => return None,
            };
        }
    }

    let mut rgb = vec![0u32; width * height];
    for (i, px) in rgb.iter_mut().enumerate() {
        let o = i * channels;
        let (r, g, b) = match channels {
            1 => (out[o], out[o], out[o]),
            _ => (out[o], out[o + 1], out[o + 2]),
        };
        *px = ((r as u32) << 16) | ((g as u32) << 8) | b as u32;
    }
    Some(Image { width, height, rgb })
}

/// The PNG Paeth predictor: pick whichever neighbour the gradient points at.
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i32 + b as i32 - c as i32;
    let (pa, pb, pc) = ((p - a as i32).abs(), (p - b as i32).abs(), (p - c as i32).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}
