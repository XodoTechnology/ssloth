//! Keyboard/mouse client->server messages, ATEN "Insyde" variants.
//! From novnc-ref/rfb.js RFB.messages:
//!   keyEventInsyde:    [4][0][down:u8][0,0][hid_usage:u32][9x 0]   = 18 bytes
//!   pointerEventInsyde:[5][0][mask:u8][x:u16][y:u16][11x 0]        = 18 bytes
//! keyEventInsyde first translates the X11 keysym to a USB HID usage code via
//! the device Keymap; we do the same before sending.
//!
//! The consoles' own input path is [`queue`] (one ordered queue per session)
//! feeding [`encoder`] (events → each family's packets); these helpers are
//! its ATEN framing and what the CLI's `--type` builds on.

pub mod encoder;
pub mod queue;

pub use encoder::{Encode, Event, FamilyEncoder};
pub use queue::InputQueue;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/keymap_table.rs"));

pub fn keysym_to_hid(keysym: u32) -> Option<u32> {
    KEYSYM_TO_HID.iter().find(|(k, _)| *k == keysym).map(|(_, h)| *h)
}

/// Build a key event from an X11 keysym (translated to HID). None if unmapped.
pub fn key_event(keysym: u32, down: bool) -> Option<[u8; 18]> {
    let hid = keysym_to_hid(keysym)?;
    let mut m = [0u8; 18];
    m[0] = 4;
    m[2] = down as u8;
    m[5..9].copy_from_slice(&hid.to_be_bytes());
    Some(m)
}

pub fn pointer_event(x: u16, y: u16, button_mask: u8) -> [u8; 18] {
    let mut m = [0u8; 18];
    m[0] = 5;
    m[2] = button_mask;
    m[3..5].copy_from_slice(&x.to_be_bytes());
    m[5..7].copy_from_slice(&y.to_be_bytes());
    m
}

/// Ctrl+Alt+Del as raw HID usages: LeftCtrl 0xE0, LeftAlt 0xE2, Delete 0x4C.
/// Press all three, then release in reverse — six 18-byte key events concatenated.
pub fn ctrl_alt_del() -> Vec<u8> {
    let mut out = Vec::with_capacity(18 * 6);
    for hid in [0xE0u32, 0xE2, 0x4C] { out.extend_from_slice(&hid_event(hid, true)); }
    for hid in [0x4Cu32, 0xE2, 0xE0] { out.extend_from_slice(&hid_event(hid, false)); }
    out
}

/// A key event straight from a HID usage code (bypasses the keysym map).
pub fn hid_event(hid: u32, down: bool) -> [u8; 18] {
    let mut m = [0u8; 18];
    m[0] = 4;
    m[2] = down as u8;
    m[5..9].copy_from_slice(&hid.to_be_bytes());
    m
}

/// How to type `c` on a US keyboard: the keysym of the key itself (always the
/// unshifted one, since that is what maps to a HID usage), whether Shift is
/// held, and the character's own keysym (what a plain RFB server expects with
/// Shift down). None for characters no key produces — they are skipped rather
/// than guessed at.
pub fn char_keystroke(c: char) -> Option<(u32, bool, u32)> {
    const SHIFTED: [(char, char); 21] = [
        ('!', '1'), ('@', '2'), ('#', '3'), ('$', '4'), ('%', '5'), ('^', '6'), ('&', '7'),
        ('*', '8'), ('(', '9'), (')', '0'), ('_', '-'), ('+', '='), ('{', '['), ('}', ']'),
        ('|', '\\'), (':', ';'), ('"', '\''), ('<', ','), ('>', '.'), ('?', '/'), ('~', '`'),
    ];
    Some(match c {
        '\n' | '\r' => (0xff0d, false, 0xff0d),
        '\t' => (0xff09, false, 0xff09),
        'a'..='z' | '0'..='9' | ' ' | '-' | '=' | '[' | ']' | '\\' | ';' | '\'' | ',' | '.'
        | '/' | '`' => (c as u32, false, c as u32),
        'A'..='Z' => (c.to_ascii_lowercase() as u32, true, c as u32),
        _ => {
            let base = SHIFTED.iter().find(|(s, _)| *s == c)?.1;
            (base as u32, true, c as u32)
        }
    })
}

/// X11 keysyms for the modifiers, which the GUI derives from its modifier
/// state each frame.
pub const MOD_SHIFT: u32 = 0xffe1; // Left Shift
pub const MOD_CTRL: u32 = 0xffe3;  // Left Ctrl
pub const MOD_ALT: u32 = 0xffe9;   // Left Alt
