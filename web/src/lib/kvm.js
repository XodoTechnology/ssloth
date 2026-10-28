// KVM console client lib — KVMF wire decode + canvas painter + HID input map.
// Wire format matches bmc-core's frame_pump encode (vendored): 16B header
// (magic 'KVMF' u32 LE, version u8, flags u8, nrects u16, seq u32, w u16,
// h u16) then n×16B rect entries (x,y,w,h u16, fmt u8, pad, len u32) then
// 4-aligned pixel data per rect. fmt 0=BGRX(4B/px), 1=RGB5551(2B/px).

export const KVM_HEADER = 16;
export const KVM_RECT = 16;
export const KVM_FULL = 1;

export function decodeFrame(buf) {
  const v = new DataView(buf);
  if (buf.byteLength < KVM_HEADER || v.getUint32(0, true) !== 0x464d564b || v.getUint8(4) !== 1) {
    throw new Error('not a version 1 KVMF frame');
  }
  const n = v.getUint16(6, true);
  const width = v.getUint16(12, true);
  const height = v.getUint16(14, true);
  const rects = [];
  let off = KVM_HEADER + KVM_RECT * n;
  for (let i = 0; i < n; i++) {
    const e = KVM_HEADER + KVM_RECT * i;
    const len = v.getUint32(e + 12, true);
    const r = { x: v.getUint16(e, true), y: v.getUint16(e + 2, true), w: v.getUint16(e + 4, true), h: v.getUint16(e + 6, true), fmt: v.getUint8(e + 8), off, len };
    if (r.fmt !== 0 && r.fmt !== 1) throw new Error(`rect ${i} unknown format ${r.fmt}`);
    if (len !== r.w * r.h * (r.fmt ? 2 : 4)) throw new Error(`rect ${i} bad length`);
    if (r.x + r.w > width || r.y + r.h > height) throw new Error(`rect ${i} out of bounds`);
    rects.push(r);
    off += (len + 3) & ~3;
  }
  return { buf, flags: v.getUint8(5), seq: v.getUint32(8, true), width, height, rects };
}

function from5551(v16) {
  return ((v16 & 0xf800) << 8) | ((v16 & 0x07c0) << 5) | ((v16 & 0x003e) << 2);
}

// Paint all rects of a decoded frame into the canvas (canvas sized to
// frame.width×frame.height by the caller on resize/full).
export function paintFrame(ctx, frame) {
  const bytes = new Uint8Array(frame.buf);
  for (const r of frame.rects) {
    const img = ctx.createImageData(r.w, r.h);
    const out = img.data;
    if (r.fmt === 1) {
      const src = new Uint16Array(frame.buf.slice(r.off, r.off + r.len));
      for (let i = 0; i < r.w * r.h; i++) {
        const p = from5551(src[i]);
        out[i * 4] = (p >> 16) & 0xff;
        out[i * 4 + 1] = (p >> 8) & 0xff;
        out[i * 4 + 2] = p & 0xff;
        out[i * 4 + 3] = 255;
      }
    } else {
      for (let i = 0; i < r.w * r.h; i++) {
        const b = r.off + i * 4;
        out[i * 4] = bytes[b + 2];
        out[i * 4 + 1] = bytes[b + 1];
        out[i * 4 + 2] = bytes[b];
        out[i * 4 + 3] = 255;
      }
    }
    ctx.putImageData(img, r.x, r.y);
  }
}

// DOM KeyboardEvent.code → USB HID usage (keyboard page). Ported from
// bmc-kvm's ui/console/input.ts (spike S2 table).
const range = (codes, base) => Object.fromEntries(codes.map((c, i) => [c, base + i]));
export const CODE_TO_HID = {
  ...range([...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].map((c) => `Key${c}`), 0x04),
  ...range(['Digit1', 'Digit2', 'Digit3', 'Digit4', 'Digit5', 'Digit6', 'Digit7', 'Digit8', 'Digit9', 'Digit0'], 0x1e),
  Enter: 0x28, Escape: 0x29, Backspace: 0x2a, Tab: 0x2b, Space: 0x2c,
  Minus: 0x2d, Equal: 0x2e, BracketLeft: 0x2f, BracketRight: 0x30,
  Backslash: 0x31, Semicolon: 0x33, Quote: 0x34, Backquote: 0x35, Comma: 0x36, Period: 0x37, Slash: 0x38,
  CapsLock: 0x39,
  ...range(['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'], 0x3a),
  PrintScreen: 0x46, ScrollLock: 0x47, Pause: 0x48,
  Insert: 0x49, Home: 0x4a, PageUp: 0x4b, Delete: 0x4c, End: 0x4d, PageDown: 0x4e,
  ArrowRight: 0x4f, ArrowLeft: 0x50, ArrowDown: 0x51, ArrowUp: 0x52,
  NumLock: 0x53, NumpadDivide: 0x54, NumpadMultiply: 0x55, NumpadSubtract: 0x56, NumpadAdd: 0x57, NumpadEnter: 0x58,
  ...range(['Numpad1', 'Numpad2', 'Numpad3', 'Numpad4', 'Numpad5', 'Numpad6', 'Numpad7', 'Numpad8', 'Numpad9', 'Numpad0'], 0x59),
  NumpadDecimal: 0x63, IntlBackslash: 0x64, ContextMenu: 0x65,
  ControlLeft: 0xe0, ShiftLeft: 0xe1, AltLeft: 0xe2, MetaLeft: 0xe3,
  ControlRight: 0xe4, ShiftRight: 0xe5, AltRight: 0xe6, MetaRight: 0xe7,
};

const HID_ALIASES = { OSLeft: 'MetaLeft', OSRight: 'MetaRight', VolumeMute: 'AudioVolumeMute', VolumeUp: 'AudioVolumeUp', VolumeDown: 'AudioVolumeDown', Hiragana: 'Lang4', Katakana: 'Lang3' };

export function hidFor(code) {
  return CODE_TO_HID[HID_ALIASES[code] ?? code] ?? null;
}

// US layout paste-as-keystrokes.
const US_PLAIN = "abcdefghijklmnopqrstuvwxyz1234567890\n\t -=[]\\;'`,./";
const US_SHIFT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()\n\t _+{}|:"~<>?';
const US_USAGE = [
  ...Array.from({ length: 26 }, (_, i) => 0x04 + i),
  ...Array.from({ length: 10 }, (_, i) => 0x1e + i),
  0x28, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];
export function usKey(ch) {
  if (ch === '\r') return null;
  let i = US_PLAIN.indexOf(ch);
  if (i >= 0) return { usage: US_USAGE[i], shift: false };
  i = US_SHIFT.indexOf(ch);
  if (i >= 0) return { usage: US_USAGE[i], shift: true };
  return null;
}
