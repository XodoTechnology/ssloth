'use strict';

// Generates the PWA icons: dark rounded square + emerald ">_" terminal glyph.
// Raw PNG encoder (zlib + manual CRC) — no image deps needed.
//   node scripts/gen-icons.js
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const BG = [10, 13, 16];      // ink-950
const FG = [52, 211, 153];    // emerald-400

function crc32(buf) {
  let table = crc32.t;
  if (!table) {
    table = crc32.t = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
  }
  let c = ~0;
  for (const b of buf) c = table[(c ^ b) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function png(size) {
  const px = Buffer.alloc(size * size * 3);
  const radius = size * 0.22;
  // glyph geometry (in icon-relative units): chevron ">_" centred
  const t = size * 0.075;              // stroke thickness
  const cx = size * 0.5, cy = size * 0.48;
  const arm = size * 0.14;             // chevron arm length
  const ux = size * 0.30, uy = size * 0.66, uw = size * 0.16; // underscore

  const inRoundedRect = (x, y) =>
    x >= radius && x < size - radius || y >= radius && y < size - radius
      ? true
      : (x - radius) ** 2 + (y - radius) ** 2 < radius ** 2 ||
        (x - (size - radius)) ** 2 + (y - radius) ** 2 < radius ** 2 ||
        (x - radius) ** 2 + (y - (size - radius)) ** 2 < radius ** 2 ||
        (x - (size - radius)) ** 2 + (y - (size - radius)) ** 2 < radius ** 2;

  const distToSeg = (px_, py_, x1, y1, x2, y2) => {
    const dx = x2 - x1, dy = y2 - y1;
    const tt = Math.max(0, Math.min(1, ((px_ - x1) * dx + (py_ - y1) * dy) / (dx * dx + dy * dy)));
    return Math.hypot(px_ - (x1 + tt * dx), py_ - (y1 + tt * dy));
  };

  // chevron: two segments forming ">"
  const gx = cx - arm * 0.9;
  const tip = [gx + arm * 1.6, cy];
  const top = [gx, cy - arm];
  const bot = [gx, cy + arm];

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 3;
      let c = BG;
      if (inRoundedRect(x + 0.5, y + 0.5)) {
        const d = Math.min(distToSeg(x, y, ...top, ...tip), distToSeg(x, y, ...bot, ...tip));
        const inChevron = d < t;
        const inDash = x > cx + arm * 0.4 - uw && x < cx + arm * 0.4 + uw && y > uy - t / 2 && y < uy + t / 2;
        if (inChevron || inDash) c = FG;
      }
      px[i] = c[0];
      px[i + 1] = c[1];
      px[i + 2] = c[2];
    }
  }

  // scanlines with filter byte 0
  const raw = Buffer.alloc(size * (size * 3 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 3 + 1)] = 0;
    px.copy(raw, y * (size * 3 + 1) + 1, y * size * 3, (y + 1) * size * 3);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // truecolor
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const outDir = path.join(__dirname, '..', 'web', 'public', 'icons');
fs.mkdirSync(outDir, { recursive: true });
for (const s of [192, 512]) {
  const f = path.join(outDir, `icon-${s}.png`);
  fs.writeFileSync(f, png(s));
  console.log('wrote', f, fs.statSync(f).size, 'bytes');
}
