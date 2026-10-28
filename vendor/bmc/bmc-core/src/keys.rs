//! Keys by position: W3C `KeyboardEvent.code` → USB HID keyboard-page usage,
//! and the usage → X11 keysym step iDRAC 9's plain RFB needs.
//!
//! A code names a physical key, not a character, so the remote's own layout
//! decides what a key types (Tauri spec, "Console › Input"). Every family but
//! iDRAC 9 wants HID usages; RFB wants keysyms, which here are the unshifted
//! US ones — the same thing a US keyboard's X server reports for the key, and
//! what `keymap_table.rs` mapped back from before codes existed.
//!
//! The table is spike S2's (`ui/src/lib/console/input.ts`), keyboard page only:
//! BMC virtual keyboards are boot keyboards, so consumer-page keys cannot be
//! sent. `ui/src/lib/console/code-hid-golden.txt` is generated from it and
//! checked by both sides, so the page and core cannot drift.

/// W3C code → HID usage (page 0x07), sorted by usage.
pub const CODE_TO_HID: &[(&str, u16)] = &[
    ("KeyA", 0x04), ("KeyB", 0x05), ("KeyC", 0x06), ("KeyD", 0x07), ("KeyE", 0x08),
    ("KeyF", 0x09), ("KeyG", 0x0a), ("KeyH", 0x0b), ("KeyI", 0x0c), ("KeyJ", 0x0d),
    ("KeyK", 0x0e), ("KeyL", 0x0f), ("KeyM", 0x10), ("KeyN", 0x11), ("KeyO", 0x12),
    ("KeyP", 0x13), ("KeyQ", 0x14), ("KeyR", 0x15), ("KeyS", 0x16), ("KeyT", 0x17),
    ("KeyU", 0x18), ("KeyV", 0x19), ("KeyW", 0x1a), ("KeyX", 0x1b), ("KeyY", 0x1c),
    ("KeyZ", 0x1d),
    ("Digit1", 0x1e), ("Digit2", 0x1f), ("Digit3", 0x20), ("Digit4", 0x21), ("Digit5", 0x22),
    ("Digit6", 0x23), ("Digit7", 0x24), ("Digit8", 0x25), ("Digit9", 0x26), ("Digit0", 0x27),
    ("Enter", 0x28), ("Escape", 0x29), ("Backspace", 0x2a), ("Tab", 0x2b), ("Space", 0x2c),
    ("Minus", 0x2d), ("Equal", 0x2e), ("BracketLeft", 0x2f), ("BracketRight", 0x30),
    // The ISO '#~' key reports Backslash too; hosts treat 0x31 and 0x32 alike.
    ("Backslash", 0x31), ("Semicolon", 0x33), ("Quote", 0x34), ("Backquote", 0x35),
    ("Comma", 0x36), ("Period", 0x37), ("Slash", 0x38), ("CapsLock", 0x39),
    ("F1", 0x3a), ("F2", 0x3b), ("F3", 0x3c), ("F4", 0x3d), ("F5", 0x3e), ("F6", 0x3f),
    ("F7", 0x40), ("F8", 0x41), ("F9", 0x42), ("F10", 0x43), ("F11", 0x44), ("F12", 0x45),
    ("PrintScreen", 0x46), ("ScrollLock", 0x47), ("Pause", 0x48),
    ("Insert", 0x49), ("Home", 0x4a), ("PageUp", 0x4b), ("Delete", 0x4c), ("End", 0x4d),
    ("PageDown", 0x4e), ("ArrowRight", 0x4f), ("ArrowLeft", 0x50), ("ArrowDown", 0x51),
    ("ArrowUp", 0x52),
    ("NumLock", 0x53), ("NumpadDivide", 0x54), ("NumpadMultiply", 0x55),
    ("NumpadSubtract", 0x56), ("NumpadAdd", 0x57), ("NumpadEnter", 0x58),
    ("Numpad1", 0x59), ("Numpad2", 0x5a), ("Numpad3", 0x5b), ("Numpad4", 0x5c),
    ("Numpad5", 0x5d), ("Numpad6", 0x5e), ("Numpad7", 0x5f), ("Numpad8", 0x60),
    ("Numpad9", 0x61), ("Numpad0", 0x62), ("NumpadDecimal", 0x63),
    ("IntlBackslash", 0x64), ("ContextMenu", 0x65), ("Power", 0x66), ("NumpadEqual", 0x67),
    ("F13", 0x68), ("F14", 0x69), ("F15", 0x6a), ("F16", 0x6b), ("F17", 0x6c), ("F18", 0x6d),
    ("F19", 0x6e), ("F20", 0x6f), ("F21", 0x70), ("F22", 0x71), ("F23", 0x72), ("F24", 0x73),
    ("Open", 0x74), ("Help", 0x75), ("Select", 0x77), ("Again", 0x79), ("Undo", 0x7a),
    ("Cut", 0x7b), ("Copy", 0x7c), ("Paste", 0x7d), ("Find", 0x7e),
    ("AudioVolumeMute", 0x7f), ("AudioVolumeUp", 0x80), ("AudioVolumeDown", 0x81),
    ("NumpadComma", 0x85), ("IntlRo", 0x87), ("KanaMode", 0x88), ("IntlYen", 0x89),
    ("Convert", 0x8a), ("NonConvert", 0x8b),
    ("Lang1", 0x90), ("Lang2", 0x91), ("Lang3", 0x92), ("Lang4", 0x93), ("Lang5", 0x94),
    ("Props", 0xa3), ("NumpadParenLeft", 0xb6), ("NumpadParenRight", 0xb7),
    ("NumpadBackspace", 0xbb), ("NumpadHash", 0xcc),
    ("NumpadMemoryStore", 0xd0), ("NumpadMemoryRecall", 0xd1), ("NumpadMemoryClear", 0xd2),
    ("NumpadMemoryAdd", 0xd3), ("NumpadMemorySubtract", 0xd4),
    ("NumpadClear", 0xd8), ("NumpadClearEntry", 0xd9),
    ("ControlLeft", 0xe0), ("ShiftLeft", 0xe1), ("AltLeft", 0xe2), ("MetaLeft", 0xe3),
    // AltGr arrives as code AltRight with key "AltGraph".
    ("ControlRight", 0xe4), ("ShiftRight", 0xe5), ("AltRight", 0xe6), ("MetaRight", 0xe7),
];

/// Legacy names some engines still send. WebKitGTK 2.54 reports Super as
/// OSLeft/OSRight (spike S2), and without this Super would be dropped.
pub const ALIASES: &[(&str, &str)] = &[
    ("OSLeft", "MetaLeft"), ("OSRight", "MetaRight"),
    ("VolumeMute", "AudioVolumeMute"), ("VolumeUp", "AudioVolumeUp"),
    ("VolumeDown", "AudioVolumeDown"),
    ("Hiragana", "Lang4"), ("Katakana", "Lang3"),
];

pub fn normalise(code: &str) -> &str {
    ALIASES.iter().find(|(a, _)| *a == code).map_or(code, |(_, c)| c)
}

/// The usage a code sends, or None: an unknown or unsendable code is dropped.
pub fn code_to_hid(code: &str) -> Option<u16> {
    let code = normalise(code);
    CODE_TO_HID.iter().find(|(c, _)| *c == code).map(|(_, u)| *u)
}

/// The modifier usages, LeftControl 0xE0 … RightGUI 0xE7.
pub fn is_modifier(usage: u16) -> bool {
    (0xe0..=0xe7).contains(&usage)
}

/// Usage 0xE0 + i is bit i of the boot report's modifier byte: LCtrl 0x01,
/// LShift 0x02, LAlt 0x04, LGui 0x08, then the right-hand four.
pub const MODIFIER_BIT: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

/// The modifier-byte bit for a modifier usage, 0 for any other key.
pub fn modifier_bit(usage: u16) -> u8 {
    if is_modifier(usage) { MODIFIER_BIT[usize::from(usage - 0xe0)] } else { 0 }
}

/// The unshifted US keysym for a usage: the step iDRAC 9's RFB takes. None for
/// a key that has no keysym a US X server would report, which is dropped there.
///
/// MetaLeft is Super_L, 0xFFEB. `keymap_table.rs` maps 0xFFE7 (Meta_L) to
/// 65337, which is no usage at all; going from the code avoids that entry.
pub fn hid_to_keysym(usage: u16) -> Option<u32> {
    Some(match usage {
        0x04..=0x1d => u32::from(b'a') + u32::from(usage - 0x04),
        0x1e..=0x26 => u32::from(b'1') + u32::from(usage - 0x1e),
        0x27 => 0x30,
        0x28 => 0xff0d, // Return
        0x29 => 0xff1b, // Escape
        0x2a => 0xff08, // BackSpace
        0x2b => 0xff09, // Tab
        0x2c => 0x20,
        0x2d => 0x2d, // minus
        0x2e => 0x3d, // equal
        0x2f => 0x5b, // bracketleft
        0x30 => 0x5d, // bracketright
        0x31 => 0x5c, // backslash
        0x33 => 0x3b, // semicolon
        0x34 => 0x27, // apostrophe
        0x35 => 0x60, // grave
        0x36 => 0x2c, // comma
        0x37 => 0x2e, // period
        0x38 => 0x2f, // slash
        0x39 => 0xffe5, // Caps_Lock
        0x3a..=0x45 => 0xffbe + u32::from(usage - 0x3a), // F1..F12
        0x46 => 0xff61, // Print
        0x47 => 0xff14, // Scroll_Lock
        0x48 => 0xff13, // Pause
        0x49 => 0xff63, // Insert
        0x4a => 0xff50, // Home
        0x4b => 0xff55, // Prior
        0x4c => 0xffff, // Delete
        0x4d => 0xff57, // End
        0x4e => 0xff56, // Next
        0x4f => 0xff53, // Right
        0x50 => 0xff51, // Left
        0x51 => 0xff54, // Down
        0x52 => 0xff52, // Up
        0x53 => 0xff7f, // Num_Lock
        0x54 => 0xffaf, // KP_Divide
        0x55 => 0xffaa, // KP_Multiply
        0x56 => 0xffad, // KP_Subtract
        0x57 => 0xffab, // KP_Add
        0x58 => 0xff8d, // KP_Enter
        0x59..=0x61 => 0xffb1 + u32::from(usage - 0x59), // KP_1..KP_9
        0x62 => 0xffb0, // KP_0
        0x63 => 0xffae, // KP_Decimal
        0x65 => 0xff67, // Menu
        0x67 => 0xffbd, // KP_Equal
        0x68..=0x73 => 0xffca + u32::from(usage - 0x68), // F13..F24
        0x75 => 0xff6a, // Help
        0x77 => 0xff60, // Select
        0x79 => 0xff66, // Redo
        0x7a => 0xff65, // Undo
        0x7e => 0xff68, // Find
        0x85 => 0xffac, // KP_Separator
        0x88 => 0xff27, // Hiragana_Katakana
        0x8a => 0xff23, // Henkan_Mode
        0x8b => 0xff22, // Muhenkan
        0xe0 => 0xffe3, // Control_L
        0xe1 => 0xffe1, // Shift_L
        0xe2 => 0xffe9, // Alt_L
        0xe3 => 0xffeb, // Super_L
        0xe4 => 0xffe4, // Control_R
        0xe5 => 0xffe2, // Shift_R
        0xe6 => 0xffea, // Alt_R
        0xe7 => 0xffec, // Super_R
        _ => return None,
    })
}

/// The golden file's text: `code<TAB>0xUU` per line, sorted by code.
pub fn golden_table() -> String {
    let mut rows: Vec<_> = CODE_TO_HID.iter().collect();
    rows.sort_by_key(|(c, _)| *c);
    let mut s = String::from(
        "# W3C KeyboardEvent.code -> USB HID usage (keyboard page), generated by\n\
         # bmc-core's keys::tests::golden_table_is_current (BMC_UPDATE_GOLDEN=1 rewrites\n\
         # it). input.ts's CODE_TO_HID must carry exactly these rows.\n",
    );
    for (c, u) in rows {
        s.push_str(&format!("{c}\t0x{u:02x}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HID Usage Tables 1.4, §10 (Keyboard/Keypad page 0x07), transcribed by
    /// usage position, independently of the table above.
    fn usage_tables() -> Vec<(String, u16)> {
        let mut t: Vec<(String, u16)> = Vec::new();
        let mut run = |names: &[&str], first: u16| {
            for (i, n) in names.iter().enumerate() {
                t.push((n.to_string(), first + i as u16));
            }
        };
        let letters: Vec<String> = ('A'..='Z').map(|c| format!("Key{c}")).collect();
        run(&letters.iter().map(String::as_str).collect::<Vec<_>>(), 0x04);
        run(&["Digit1", "Digit2", "Digit3", "Digit4", "Digit5", "Digit6", "Digit7", "Digit8",
              "Digit9", "Digit0"], 0x1e);
        run(&["Enter", "Escape", "Backspace", "Tab", "Space", "Minus", "Equal", "BracketLeft",
              "BracketRight", "Backslash"], 0x28);
        run(&["Semicolon", "Quote", "Backquote", "Comma", "Period", "Slash", "CapsLock"], 0x33);
        run(&["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12"], 0x3a);
        run(&["PrintScreen", "ScrollLock", "Pause", "Insert", "Home", "PageUp", "Delete", "End",
              "PageDown", "ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp"], 0x46);
        run(&["NumLock", "NumpadDivide", "NumpadMultiply", "NumpadSubtract", "NumpadAdd",
              "NumpadEnter", "Numpad1", "Numpad2", "Numpad3", "Numpad4", "Numpad5", "Numpad6",
              "Numpad7", "Numpad8", "Numpad9", "Numpad0", "NumpadDecimal", "IntlBackslash",
              "ContextMenu", "Power", "NumpadEqual"], 0x53);
        run(&["F13", "F14", "F15", "F16", "F17", "F18", "F19", "F20", "F21", "F22", "F23", "F24",
              "Open", "Help"], 0x68);
        run(&["Select"], 0x77);
        run(&["Again", "Undo", "Cut", "Copy", "Paste", "Find", "AudioVolumeMute",
              "AudioVolumeUp", "AudioVolumeDown"], 0x79);
        run(&["NumpadComma"], 0x85);
        run(&["IntlRo", "KanaMode", "IntlYen", "Convert", "NonConvert"], 0x87);
        run(&["Lang1", "Lang2", "Lang3", "Lang4", "Lang5"], 0x90);
        run(&["Props"], 0xa3);
        run(&["NumpadParenLeft", "NumpadParenRight"], 0xb6);
        run(&["NumpadBackspace"], 0xbb);
        run(&["NumpadHash"], 0xcc);
        run(&["NumpadMemoryStore", "NumpadMemoryRecall", "NumpadMemoryClear", "NumpadMemoryAdd",
              "NumpadMemorySubtract"], 0xd0);
        run(&["NumpadClear", "NumpadClearEntry"], 0xd8);
        run(&["ControlLeft", "ShiftLeft", "AltLeft", "MetaLeft", "ControlRight", "ShiftRight",
              "AltRight", "MetaRight"], 0xe0);
        t
    }

    #[test]
    fn table_matches_hid_usage_tables() {
        let spec = usage_tables();
        for (code, usage) in &spec {
            assert_eq!(code_to_hid(code), Some(*usage), "{code}");
        }
        for (code, usage) in CODE_TO_HID {
            assert!(spec.iter().any(|(c, u)| c == code && u == usage), "{code} 0x{usage:02x} is not in the spec");
        }
        assert_eq!(spec.len(), CODE_TO_HID.len());
    }

    #[test]
    fn aliases_normalise() {
        assert_eq!(code_to_hid("OSLeft"), Some(0xe3));
        assert_eq!(code_to_hid("OSRight"), Some(0xe7));
        assert_eq!(code_to_hid("MetaLeft"), Some(227));
        assert_eq!(code_to_hid("MetaRight"), Some(231));
        assert_eq!(code_to_hid("VolumeUp"), code_to_hid("AudioVolumeUp"));
        assert_eq!(code_to_hid("Hiragana"), Some(0x93));
        assert_eq!(code_to_hid("Katakana"), Some(0x92));
        assert_eq!(code_to_hid("NoSuchKey"), None);
        assert_eq!(code_to_hid(""), None);
    }

    #[test]
    fn modifier_bits() {
        assert_eq!(modifier_bit(0xe0), 0x01);
        assert_eq!(modifier_bit(0xe1), 0x02);
        assert_eq!(modifier_bit(0xe2), 0x04);
        assert_eq!(modifier_bit(0xe7), 0x80);
        assert_eq!(modifier_bit(0x04), 0);
    }

    /// Values from X11's keysymdef.h.
    #[test]
    fn keysyms_match_x11() {
        let k = |code: &str| hid_to_keysym(code_to_hid(code).unwrap());
        for (i, c) in ('a'..='z').enumerate() {
            assert_eq!(k(&format!("Key{}", c.to_ascii_uppercase())), Some(0x61 + i as u32));
        }
        assert_eq!(k("Digit1"), Some(0x31));
        assert_eq!(k("Digit0"), Some(0x30));
        assert_eq!(k("Enter"), Some(0xff0d));
        assert_eq!(k("Escape"), Some(0xff1b));
        assert_eq!(k("F1"), Some(0xffbe));
        assert_eq!(k("F12"), Some(0xffc9));
        assert_eq!(k("F13"), Some(0xffca));
        assert_eq!(k("ArrowLeft"), Some(0xff51));
        assert_eq!(k("ArrowUp"), Some(0xff52));
        assert_eq!(k("ArrowRight"), Some(0xff53));
        assert_eq!(k("ArrowDown"), Some(0xff54));
        assert_eq!(k("Delete"), Some(0xffff));
        assert_eq!(k("ShiftLeft"), Some(0xffe1));
        assert_eq!(k("ShiftRight"), Some(0xffe2));
        assert_eq!(k("ControlLeft"), Some(0xffe3));
        assert_eq!(k("AltLeft"), Some(0xffe9));
        assert_eq!(k("MetaLeft"), Some(0xffeb));
        assert_eq!(k("Numpad1"), Some(0xffb1));
        assert_eq!(k("Numpad0"), Some(0xffb0));
        assert_eq!(k("NumpadEnter"), Some(0xff8d));
        assert_eq!(k("CapsLock"), Some(0xffe5));
        // Keys with no US keysym are dropped rather than guessed at.
        assert_eq!(k("IntlBackslash"), None);
    }

    /// The keys egui maps today (`bmc-kvm-egui`'s `gui_keys::keysym_for`),
    /// transcribed with the code each one is: switching egui from keysyms to
    /// codes must not change a single usage or keysym.
    pub const EGUI_KEYS: &[(&str, u32)] = &[
        ("KeyA", 0x61), ("KeyB", 0x62), ("KeyC", 0x63), ("KeyD", 0x64), ("KeyE", 0x65),
        ("KeyF", 0x66), ("KeyG", 0x67), ("KeyH", 0x68), ("KeyI", 0x69), ("KeyJ", 0x6a),
        ("KeyK", 0x6b), ("KeyL", 0x6c), ("KeyM", 0x6d), ("KeyN", 0x6e), ("KeyO", 0x6f),
        ("KeyP", 0x70), ("KeyQ", 0x71), ("KeyR", 0x72), ("KeyS", 0x73), ("KeyT", 0x74),
        ("KeyU", 0x75), ("KeyV", 0x76), ("KeyW", 0x77), ("KeyX", 0x78), ("KeyY", 0x79),
        ("KeyZ", 0x7a),
        ("Digit0", 0x30), ("Digit1", 0x31), ("Digit2", 0x32), ("Digit3", 0x33), ("Digit4", 0x34),
        ("Digit5", 0x35), ("Digit6", 0x36), ("Digit7", 0x37), ("Digit8", 0x38), ("Digit9", 0x39),
        ("Space", 0x20), ("Enter", 0xff0d), ("Backspace", 0xff08), ("Tab", 0xff09),
        ("Escape", 0xff1b), ("Delete", 0xffff), ("Insert", 0xff63), ("Home", 0xff50),
        ("End", 0xff57), ("PageUp", 0xff55), ("PageDown", 0xff56),
        ("ArrowLeft", 0xff51), ("ArrowUp", 0xff52), ("ArrowRight", 0xff53), ("ArrowDown", 0xff54),
        ("F1", 0xffbe), ("F2", 0xffbf), ("F3", 0xffc0), ("F4", 0xffc1), ("F5", 0xffc2),
        ("F6", 0xffc3), ("F7", 0xffc4), ("F8", 0xffc5), ("F9", 0xffc6), ("F10", 0xffc7),
        ("F11", 0xffc8), ("F12", 0xffc9),
        ("Minus", 0x2d), ("Equal", 0x3d), ("BracketLeft", 0x5b), ("BracketRight", 0x5d),
        ("Backslash", 0x5c), ("Semicolon", 0x3b), ("Quote", 0x27), ("Comma", 0x2c),
        ("Period", 0x2e), ("Slash", 0x2f), ("Backquote", 0x60),
        // The modifiers egui derives from its modifier state (input::MOD_*).
        ("ShiftLeft", 0xffe1), ("ControlLeft", 0xffe3), ("AltLeft", 0xffe9),
    ];

    #[test]
    fn legacy_keysyms_agree() {
        for (code, keysym) in EGUI_KEYS {
            let usage = code_to_hid(code).unwrap();
            assert_eq!(crate::input::keysym_to_hid(*keysym), Some(u32::from(usage)), "{code}");
            assert_eq!(hid_to_keysym(usage), Some(*keysym), "{code}");
        }
    }

    #[test]
    fn golden_table_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ui/src/lib/console/code-hid-golden.txt");
        let want = golden_table();
        if std::env::var_os("BMC_UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &want).unwrap();
        }
        let have = std::fs::read_to_string(path).expect("code-hid-golden.txt");
        assert_eq!(have.replace("\r\n", "\n"), want, "rerun with BMC_UPDATE_GOLDEN=1");
    }
}
