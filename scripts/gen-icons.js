'use strict';

// Generates the app icons — a geometric sloth face matching web/public/sloth.svg.
// Parametric SDF shapes + 2x2 supersampling, raw PNG encoder (zlib + manual
// CRC) — no image deps needed.
//   node scripts/gen-icons.js
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];

const INK = hex('#0a0d10');
const EMERALD_DARK = hex('#2aa87a');
const FUR = hex('#7a5a38');
const MASK = hex('#ecdfc6');
const PATCH = hex('#4c3d2a');
const EYE = hex('#f8f1df');
const DARK = hex('#3a2c1c');
const PUPIL = hex('#2c2115');
const WHITE = hex('#ffffff');

// ---- shape tests in 0..256 unit space (topmost covering layer wins) ----

const rr = (u, v, inset, rad) => {
  const x0 = inset, y0 = inset, x1 = 256 - inset, y1 = 256 - inset;
  if (u < x0 || u > x1 || v < y0 || v > y1) return false;
  const cx = Math.max(x0 + rad, Math.min(x1 - rad, u));
  const cy = Math.max(y0 + rad, Math.min(y1 - rad, v));
  return (u - cx) ** 2 + (v - cy) ** 2 <= rad * rad;
};

const ell = (u, v, cx, cy, rx, ry, deg = 0) => {
  const a = (deg * Math.PI) / 180;
  const dx = u - cx, dy = v - cy;
  const x = dx * Math.cos(a) + dy * Math.sin(a);
  const y = -dx * Math.sin(a) + dy * Math.cos(a);
  return (x * x) / (rx * rx) + (y * y) / (ry * ry) <= 1;
};

const distSeg = (px, py, x1, y1, x2, y2) => {
  const dx = x2 - x1, dy = y2 - y1;
  const t = Math.max(0, Math.min(1, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
};

const nearSegs = (u, v, pts, w) => {
  for (let i = 0; i + 2 < pts.length; i += 2) {
    if (distSeg(u, v, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]) <= w) return true;
  }
  return false;
};

// Layers, topmost first (painter's algorithm via first-match).
const LAYERS = [
  // smile
  [DARK, (u, v) => nearSegs(u, v, [113, 141, 120.5, 147, 128, 148.2, 135.5, 147, 143, 141], 2.8)],
  // nose
  [DARK, (u, v) => ell(u, v, 128, 127, 7.5, 8.5)],
  // eye catchlights, pupils, whites
  [WHITE, (u, v) => ell(u, v, 98.4, 104.6, 1.3, 1.3) || ell(u, v, 160.4, 104.6, 1.3, 1.3)],
  [PUPIL, (u, v) => ell(u, v, 97, 106, 3.4, 3.4) || ell(u, v, 159, 106, 3.4, 3.4)],
  [EYE, (u, v) => ell(u, v, 97, 106, 7.5, 7.5) || ell(u, v, 159, 106, 7.5, 7.5)],
  // eye patches — slant down toward the nose, classic three-toed sloth mask
  [PATCH, (u, v) => ell(u, v, 95, 106, 25, 13, -24) || ell(u, v, 161, 106, 25, 13, 24)],
  // face mask
  [MASK, (u, v) => ell(u, v, 128, 118, 63, 55)],
  // head fur + barely-there ears
  [FUR, (u, v) => ell(u, v, 128, 114, 82, 70) || ell(u, v, 88, 57, 13, 13) || ell(u, v, 168, 57, 13, 13)],
  // background: dark fill then thin emerald ring (drawn as dark-over-emerald)
  [INK, (u, v) => rr(u, v, 6.5, 48)],
  [EMERALD_DARK, (u, v) => rr(u, v, 4, 49)],
  [INK, (u, v) => rr(u, v, 0, 52)],
];

const sample = (u, v) => {
  for (const [c, test] of LAYERS) if (test(u, v)) return c;
  return null; // transparent corner
};

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

// RGBA output (maskable/square icons keep the dark bg; corners stay rounded
// so non-maskable uses still look tidy).
function png(size) {
  const px = Buffer.alloc(size * size * 4);
  const ss = [[0.25, 0.25], [0.75, 0.25], [0.25, 0.75], [0.75, 0.75]];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (const [ox, oy] of ss) {
        const c = sample(((x + ox) / size) * 256, ((y + oy) / size) * 256);
        if (c) { r += c[0]; g += c[1]; b += c[2]; a += 255; }
      }
      const i = (y * size + x) * 4;
      const n = ss.length;
      px[i] = Math.round(r / n);
      px[i + 1] = Math.round(g / n);
      px[i + 2] = Math.round(b / n);
      px[i + 3] = Math.round(a / n);
    }
  }
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    px.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const outWeb = path.join(__dirname, '..', 'web', 'public', 'icons');
fs.mkdirSync(outWeb, { recursive: true });
for (const s of [192, 512]) {
  const f = path.join(outWeb, `icon-${s}.png`);
  fs.writeFileSync(f, png(s));
  console.log('wrote', f, fs.statSync(f).size, 'bytes');
}

// electron-builder converts this for .ico/.icns targets.
const outDesk = path.join(__dirname, '..', 'desktop', 'icon.png');
fs.writeFileSync(outDesk, png(1024));
console.log('wrote', outDesk, fs.statSync(outDesk).size, 'bytes');
