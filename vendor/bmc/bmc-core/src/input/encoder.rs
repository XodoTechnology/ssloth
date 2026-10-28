//! Console input as events, and each family's framing of them.
//!
//! A front end describes what the user did — a key by HID usage, the pointer
//! as a fraction of the screen, a release of everything held, one pasted
//! character, the Ctrl+Alt+Del macro — and [`FamilyEncoder`] turns it into the
//! packets that family's console thread sends. The held-key state, the
//! modifier byte and AMI's sequence number live here, so the egui and Tauri
//! front ends cannot frame the same keystroke differently.
//!
//! The per-family code moved here from the egui app (`app.rs`'s
//! `keystroke_packets`, the pointer block, `forward_keys`'s five family
//! branches and `send_ctrl_alt_del`, and `workspace.rs`'s
//! `release_console_keys`) and sends the same bytes, with one exception: a
//! front end reports modifiers one key at a time, so two modifiers changing in
//! the same instant go out as two transitions in usage order (Ctrl, Shift,
//! Alt) where egui's state diff used to send one combined report or its own
//! order. The host ends up holding the same set either way.

use crate::families::{avocent, ilo4, quanta, Family};
use crate::keys::{hid_to_keysym, is_modifier, modifier_bit};
use crate::vnc;

/// Pointer buttons as `Event::Pointer` carries them: RFB's order.
pub const BTN_LEFT: u8 = 1;
pub const BTN_MIDDLE: u8 = 2;
pub const BTN_RIGHT: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    /// A key by HID usage (page 0x07). `repeat` is the OS's auto-repeat.
    Key { usage: u16, down: bool, repeat: bool },
    /// The pointer at `x`, `y` in 0..=1 of the screen, over a framebuffer of
    /// `fb` pixels; buttons `BTN_*`; `wheel` positive for up, by sign only.
    Pointer { x: f32, y: f32, fb: (usize, usize), buttons: u8, wheel: i8 },
    /// Every held key and pointer button up: on blur, on a dialog, on
    /// losing window focus.
    ReleaseAll,
    /// One pasted character, typed on a US layout (`input::char_keystroke`).
    Char(char),
    /// The family's own Ctrl+Alt+Del.
    CtrlAltDel,
}

pub trait Encode: Send {
    /// Append the packets for `ev`, in send order, to `out`.
    fn encode(&mut self, ev: &Event, out: &mut Vec<Vec<u8>>);
}

pub struct FamilyEncoder {
    family: Family,
    /// Non-modifier usages held, in the order they went down.
    held: Vec<u16>,
    /// Modifiers held, as the boot report's modifier byte.
    mods: u8,
    /// AMI's IVTP HID sequence number, one per packet.
    seq: u32,
    /// The pointer as last sent: framebuffer position and buttons.
    pointer: Option<(u16, u16, u8)>,
    /// The same report as the front end gave it, so a release can resend
    /// the position with the buttons up in every family's own units.
    pointer_at: (f32, f32, (usize, usize)),
}

impl FamilyEncoder {
    pub fn new(family: Family) -> Self {
        FamilyEncoder { family, held: Vec::new(), mods: 0, seq: 0, pointer: None, pointer_at: (0.0, 0.0, (0, 0)) }
    }

    pub fn family(&self) -> Family {
        self.family
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn key(&mut self, usage: u16, down: bool, repeat: bool, out: &mut Vec<Vec<u8>>) {
        let avsp = matches!(self.family, Family::Avocent | Family::Idrac8);
        // Only AVSP forwards auto-repeat: iDRAC 8 never leaves a key held on
        // the host, so the host has nothing to repeat — held, Backspace deleted
        // one character and stopped. Everywhere else a held key repeats on the
        // host by itself.
        if repeat && !avsp {
            return;
        }
        if is_modifier(usage) {
            let bit = modifier_bit(usage);
            let before = self.mods;
            if down { self.mods |= bit } else { self.mods &= !bit }
            // A modifier is state: only a change is news to the host.
            if self.mods == before {
                return;
            }
        } else if !repeat {
            if down {
                if !self.held.contains(&usage) {
                    // iLO's report has room for six keys; a seventh is not held.
                    if self.family == Family::Ilo4 && self.held.len() >= 6 {
                        return;
                    }
                    self.held.push(usage);
                } else if self.family == Family::Ilo4 {
                    return;
                }
            } else if let Some(i) = self.held.iter().position(|&k| k == usage) {
                self.held.remove(i);
            } else if self.family == Family::Ilo4 {
                return;
            }
        }
        match self.family {
            Family::Aten => out.push(super::hid_event(u32::from(usage), down).to_vec()),
            // Plain RFB takes X11 keysyms, not usages.
            Family::Idrac9 => {
                if let Some(ks) = hid_to_keysym(usage) {
                    out.push(vnc::key_event(ks, down));
                }
            }
            // iLO takes whole 8-byte HID reports rather than per-key events,
            // so the held set is resent whenever it changes.
            Family::Ilo4 => out.push(ilo4::kvm::key_report(self.mods, &self.held_u8())),
            // AVSP sends one packet per key transition and carries no modifier
            // byte: the modifiers are ordinary usages, down and up like any other.
            Family::Avocent | Family::Idrac8 => out.push(avocent::kvm::key_packet(usage as u8, down)),
            // AMI IVTP: the modifier byte rides in every key report, and a
            // modifier change on its own is a mods-only report.
            Family::Quanta | Family::Spx => {
                let seq = self.next_seq();
                let (hid, down) = if is_modifier(usage) { (0, false) } else { (usage as u8, down) };
                out.push(quanta::kvm::key_packet(hid, down, self.mods, seq));
            }
        }
    }

    fn held_u8(&self) -> Vec<u8> {
        self.held.iter().map(|&u| u as u8).collect()
    }

    fn pointer(&mut self, rx: f32, ry: f32, (fw, fh): (usize, usize), buttons: u8, wheel: i8, out: &mut Vec<Vec<u8>>) {
        let (rx, ry) = (rx.clamp(0.0, 1.0), ry.clamp(0.0, 1.0));
        let x = (rx * fw.saturating_sub(1) as f32) as u16;
        let y = (ry * fh.saturating_sub(1) as f32) as u16;
        // Only a change goes out. The pointer used to be sent on every
        // repaint — sixty identical packets a second while it merely rested
        // on the picture — and iDRAC 8 works through its input in order, so
        // keystrokes waited behind them for seconds.
        let state = (x, y, buttons);
        self.pointer_at = (rx, ry, (fw, fh));
        if self.pointer.replace(state) == Some(state) && wheel == 0 {
            return;
        }
        let (left, mid, right) = (buttons & BTN_LEFT != 0, buttons & BTN_MIDDLE != 0, buttons & BTN_RIGHT != 0);
        let up = wheel > 0;
        match self.family {
            // RFB pointer events in framebuffer pixels, the wheel as a
            // press and release of button 4 (up) or 5 (down).
            Family::Idrac9 | Family::Aten => {
                let ev = |m: u8| -> Vec<u8> {
                    if self.family == Family::Idrac9 { vnc::pointer_event(x, y, m) } else { super::pointer_event(x, y, m).to_vec() }
                };
                out.push(ev(buttons));
                if wheel != 0 {
                    let bit = if up { 0x08 } else { 0x10 };
                    out.push(ev(buttons | bit));
                    out.push(ev(buttons));
                }
            }
            // iLO absolute mouse: x/y in 0..3000, buttons L=1 R=2 M=4.
            Family::Ilo4 => {
                use ilo4::kvm as ik;
                let (ax, ay) = ((rx * ik::MOUSE_RANGE) as u16, (ry * ik::MOUSE_RANGE) as u16);
                let b = (left as u8 * ik::BTN_LEFT) | (right as u8 * ik::BTN_RIGHT) | (mid as u8 * ik::BTN_MIDDLE);
                out.push(ik::mouse(ax, ay, b, 0));
                if wheel != 0 {
                    out.push(ik::mouse(ax, ay, b, if up { 1 } else { -1 }));
                    out.push(ik::mouse(ax, ay, b, 0));
                }
            }
            // Avocent absolute mouse: framebuffer pixels, buttons L=1 R=2
            // M=4, the wheel a signed count (positive is up).
            Family::Avocent | Family::Idrac8 => {
                use avocent::kvm as ak;
                let b = (left as u8 * ak::BTN_LEFT) | (right as u8 * ak::BTN_RIGHT) | (mid as u8 * ak::BTN_MIDDLE);
                out.push(ak::mouse_packet(x, y, b, 0));
                if wheel != 0 {
                    out.push(ak::mouse_packet(x, y, b, if up { 1 } else { -1 }));
                    out.push(ak::mouse_packet(x, y, b, 0));
                }
            }
            // AMI absolute mouse: x/y in 0..32767, buttons L=1 R=2 M=4. Both
            // AMI generations take the same IUSB HID packet.
            Family::Quanta | Family::Spx => {
                let (qx, qy) = ((rx * 32767.0) as u16, (ry * 32767.0) as u16);
                let qb = (left as u8) | ((right as u8) << 1) | ((mid as u8) << 2);
                let seq = self.next_seq();
                out.push(quanta::kvm::mouse_packet(qx, qy, qb, 0, seq));
                if wheel != 0 {
                    let seq = self.next_seq();
                    out.push(quanta::kvm::mouse_packet(qx, qy, qb, if up { 1 } else { -1 }, seq));
                }
            }
        }
    }

    fn release_all(&mut self, out: &mut Vec<Vec<u8>>) {
        self.release_keys(out);
        // A button held through a blur (a drag that left the window) would
        // stay pressed on the host until the next pointer report; let it go
        // where the pointer is. The egui app never released buttons here.
        if matches!(self.pointer, Some((_, _, b)) if b != 0) {
            let (rx, ry, fb) = self.pointer_at;
            self.pointer(rx, ry, fb, 0, 0, out);
        }
    }

    fn release_keys(&mut self, out: &mut Vec<Vec<u8>>) {
        if self.held.is_empty() && self.mods == 0 {
            return;
        }
        // Keys in the order they went down, then the modifiers in usage order.
        let mut ups: Vec<u16> = std::mem::take(&mut self.held);
        ups.extend((0..8u16).filter(|i| self.mods & (1 << i) != 0).map(|i| 0xe0 + i));
        self.mods = 0;
        match self.family {
            Family::Ilo4 => out.push(ilo4::kvm::key_report(0, &[])),
            Family::Aten => out.extend(ups.iter().map(|&u| super::hid_event(u32::from(u), false).to_vec())),
            Family::Idrac9 => out.extend(ups.iter().filter_map(|&u| hid_to_keysym(u)).map(|ks| vnc::key_event(ks, false))),
            Family::Avocent | Family::Idrac8 => out.extend(ups.iter().map(|&u| avocent::kvm::key_packet(u as u8, false))),
            Family::Quanta | Family::Spx => {
                for &u in &ups {
                    let seq = self.next_seq();
                    out.push(quanta::kvm::key_packet(u as u8, false, 0, seq));
                }
            }
        }
    }

    /// One character: Shift if it needs it, the key down, the key up, Shift
    /// released. Held state is not touched: a paste types between keystrokes.
    fn char(&mut self, c: char, out: &mut Vec<Vec<u8>>) {
        let Some((base, shift, own)) = super::char_keystroke(c) else { return };
        let Some(hid) = super::keysym_to_hid(base) else { return };
        let hid = hid as u8;
        match self.family {
            // Plain RFB: the character's own keysym with Shift held, as any
            // VNC client sends it.
            Family::Idrac9 => {
                if shift { out.push(vnc::key_event(super::MOD_SHIFT, true)); }
                out.push(vnc::key_event(own, true));
                out.push(vnc::key_event(own, false));
                if shift { out.push(vnc::key_event(super::MOD_SHIFT, false)); }
            }
            // Whole HID reports: the key with the Shift bit, then all up.
            Family::Ilo4 => {
                out.push(ilo4::kvm::key_report(if shift { 0x02 } else { 0 }, &[hid]));
                out.push(ilo4::kvm::key_report(0, &[]));
            }
            // One packet per transition; Shift is a key like any other (0xE1).
            Family::Avocent | Family::Idrac8 => {
                if shift { out.push(avocent::kvm::key_packet(225, true)); }
                out.push(avocent::kvm::key_packet(hid, true));
                out.push(avocent::kvm::key_packet(hid, false));
                if shift { out.push(avocent::kvm::key_packet(225, false)); }
            }
            // AMI IUSB reports carry the modifier byte in each packet.
            Family::Quanta | Family::Spx => {
                let m = if shift { 0x02 } else { 0 };
                let seq = self.next_seq();
                out.push(quanta::kvm::key_packet(hid, true, m, seq));
                let seq = self.next_seq();
                out.push(quanta::kvm::key_packet(hid, false, m, seq));
                if shift {
                    let seq = self.next_seq();
                    out.push(quanta::kvm::key_packet(0, false, 0, seq));
                }
            }
            // ATEN's Insyde key events: keysyms translated to HID usages.
            Family::Aten => {
                let mut ks = vec![(base, true), (base, false)];
                if shift {
                    ks.insert(0, (super::MOD_SHIFT, true));
                    ks.push((super::MOD_SHIFT, false));
                }
                out.extend(ks.into_iter().filter_map(|(k, d)| super::key_event(k, d)).map(|p| p.to_vec()));
            }
        }
    }

    fn ctrl_alt_del(&mut self, out: &mut Vec<Vec<u8>>) {
        match self.family {
            Family::Ilo4 => out.extend(ilo4::kvm::ctrl_alt_del()),
            // X11 keysyms: Ctrl, Alt, Delete down then up.
            Family::Idrac9 => {
                for (k, d) in [(0xffe3u32, true), (0xffe9, true), (0xffff, true),
                               (0xffff, false), (0xffe9, false), (0xffe3, false)] {
                    out.push(vnc::key_event(k, d));
                }
            }
            // Both AMI stacks: one IUSB report with Ctrl+Alt held and Delete
            // (HID usage 0x4C) pressed, then an all-up report.
            Family::Quanta | Family::Spx => {
                let seq = self.next_seq();
                out.push(quanta::kvm::key_packet(0x4C, true, 0x05, seq));
                let seq = self.next_seq();
                out.push(quanta::kvm::key_packet(0, false, 0, seq));
            }
            // AVSP has no modifier byte: Ctrl, Alt and Delete are three
            // ordinary HID usage codes, pressed and released in order. This
            // is the reference client's own macro, 224/226/76.
            Family::Avocent | Family::Idrac8 => {
                for (hid, down) in [(224u8, true), (226, true), (76, true), (76, false), (226, false), (224, false)] {
                    out.push(avocent::kvm::key_packet(hid, down));
                }
            }
            Family::Aten => out.push(super::ctrl_alt_del()),
        }
    }
}

impl Encode for FamilyEncoder {
    fn encode(&mut self, ev: &Event, out: &mut Vec<Vec<u8>>) {
        match *ev {
            Event::Key { usage, down, repeat } => self.key(usage, down, repeat, out),
            Event::Pointer { x, y, fb, buttons, wheel } => self.pointer(x, y, fb, buttons, wheel, out),
            Event::ReleaseAll => self.release_all(out),
            Event::Char(c) => self.char(c, out),
            Event::CtrlAltDel => self.ctrl_alt_del(out),
        }
    }
}

/// Each family's expected bytes are built with its packet builders exactly as
/// the egui app called them before this module existed (`bmc-kvm-egui` at
/// 4191cd8): `app.rs` 936-983 `keystroke_packets`, 1847-1926 the pointer
/// block, 1981-1999 / 2001-2034 / 2036-2064 / 2066-2088 / 2090-2105 the iDRAC 9,
/// iLO, AVSP, AMI and ATEN key branches, 2110-2145 `send_ctrl_alt_del`, and
/// `app/workspace.rs` 3101-3151 `release_console_keys`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::families::{avocent::kvm as ak, ilo4::kvm as ik, quanta::kvm as qk};
    use crate::input as aten;

    const A: u16 = 0x04;
    const B: u16 = 0x05;
    const SHIFT: u16 = 0xe1;
    const CTRL: u16 = 0xe0;
    const FB: (usize, usize) = (1024, 768);

    fn key(usage: u16, down: bool) -> Event {
        Event::Key { usage, down, repeat: false }
    }
    fn ptr(buttons: u8, wheel: i8) -> Event {
        Event::Pointer { x: 0.5, y: 0.25, fb: FB, buttons, wheel }
    }
    fn run(family: Family, evs: &[Event]) -> Vec<Vec<u8>> {
        let mut e = FamilyEncoder::new(family);
        let mut out = Vec::new();
        for ev in evs {
            e.encode(ev, &mut out);
        }
        out
    }

    /// The scripts every family is checked on, each from a fresh encoder.
    fn scripts() -> Vec<(&'static str, Vec<Event>)> {
        vec![
            ("plain", vec![key(A, true), key(A, false)]),
            ("shift+a", vec![key(SHIFT, true), key(A, true), key(A, false), key(SHIFT, false)]),
            ("repeat", vec![key(A, true), Event::Key { usage: A, down: true, repeat: true }, key(A, false)]),
            ("cad", vec![Event::CtrlAltDel]),
            ("chars", vec![Event::Char('a'), Event::Char('A'), Event::Char(':'), Event::Char('\n')]),
            ("unmapped char", vec![Event::Char('é')]),
            // A move, a right click, the same position again (nothing), wheel
            // up and down: each wheel notch resends the position around it.
            ("pointer", vec![ptr(0, 0), ptr(BTN_RIGHT, 0), ptr(0, 0), ptr(0, 0), ptr(0, 1), ptr(0, -1)]),
            ("release", vec![key(CTRL, true), key(A, true), key(B, true), Event::ReleaseAll]),
            // A drag interrupted by a blur: the button goes up where it is.
            ("release button", vec![ptr(BTN_LEFT, 0), key(A, true), Event::ReleaseAll, Event::ReleaseAll]),
            ("idle release", vec![Event::ReleaseAll]),
        ]
    }

    fn check(family: Family, want: impl Fn(&str) -> Vec<Vec<u8>>) {
        for (name, evs) in scripts() {
            assert_eq!(run(family, &evs), want(name), "{family:?} {name}");
        }
    }

    #[test]
    fn aten_sends_insyde_events() {
        let k = |ks: u32, d: bool| aten::key_event(ks, d).unwrap().to_vec();
        let p = |m: u8| aten::pointer_event(511, 191, m).to_vec();
        check(Family::Aten, |name| match name {
            "plain" => vec![k(0x61, true), k(0x61, false)],
            "shift+a" => vec![k(aten::MOD_SHIFT, true), k(0x61, true), k(0x61, false), k(aten::MOD_SHIFT, false)],
            "repeat" => vec![k(0x61, true), k(0x61, false)],
            "cad" => vec![aten::ctrl_alt_del()],
            "chars" => vec![
                k(0x61, true), k(0x61, false),
                k(aten::MOD_SHIFT, true), k(0x61, true), k(0x61, false), k(aten::MOD_SHIFT, false),
                k(aten::MOD_SHIFT, true), k(0x3b, true), k(0x3b, false), k(aten::MOD_SHIFT, false),
                k(0xff0d, true), k(0xff0d, false),
            ],
            "pointer" => vec![p(0), p(4), p(0), p(0), p(0x08), p(0), p(0), p(0x10), p(0)],
            "release" => vec![
                k(aten::MOD_CTRL, true), k(0x61, true), k(0x62, true),
                k(0x61, false), k(0x62, false), k(aten::MOD_CTRL, false),
            ],
            "release button" => vec![p(1), k(0x61, true), k(0x61, false), p(0)],
            _ => vec![],
        });
    }

    #[test]
    fn idrac9_sends_rfb_keysyms() {
        let k = |ks: u32, d: bool| vnc::key_event(ks, d);
        let p = |m: u8| vnc::pointer_event(511, 191, m);
        check(Family::Idrac9, |name| match name {
            "plain" => vec![k(0x61, true), k(0x61, false)],
            "shift+a" => vec![k(0xffe1, true), k(0x61, true), k(0x61, false), k(0xffe1, false)],
            "repeat" => vec![k(0x61, true), k(0x61, false)],
            "cad" => vec![k(0xffe3, true), k(0xffe9, true), k(0xffff, true), k(0xffff, false), k(0xffe9, false), k(0xffe3, false)],
            // Plain RFB types the character's own keysym with Shift held.
            "chars" => vec![
                k(0x61, true), k(0x61, false),
                k(0xffe1, true), k(0x41, true), k(0x41, false), k(0xffe1, false),
                k(0xffe1, true), k(0x3a, true), k(0x3a, false), k(0xffe1, false),
                k(0xff0d, true), k(0xff0d, false),
            ],
            "pointer" => vec![p(0), p(4), p(0), p(0), p(0x08), p(0), p(0), p(0x10), p(0)],
            "release" => vec![
                k(0xffe3, true), k(0x61, true), k(0x62, true),
                k(0x61, false), k(0x62, false), k(0xffe3, false),
            ],
            "release button" => vec![p(1), k(0x61, true), k(0x61, false), p(0)],
            _ => vec![],
        });
    }

    #[test]
    fn ilo4_sends_whole_reports() {
        let r = |m: u8, keys: &[u8]| ik::key_report(m, keys);
        let p = |b: u8, w: i8| ik::mouse(1500, 750, b, w);
        check(Family::Ilo4, |name| match name {
            "plain" => vec![r(0, &[4]), r(0, &[])],
            "shift+a" => vec![r(2, &[]), r(2, &[4]), r(2, &[]), r(0, &[])],
            "repeat" => vec![r(0, &[4]), r(0, &[])],
            "cad" => ik::ctrl_alt_del(),
            "chars" => vec![r(0, &[4]), r(0, &[]), r(2, &[4]), r(0, &[]), r(2, &[0x33]), r(0, &[]), r(0, &[0x28]), r(0, &[])],
            "pointer" => vec![p(0, 0), p(ik::BTN_RIGHT, 0), p(0, 0), p(0, 0), p(0, 1), p(0, 0), p(0, 0), p(0, -1), p(0, 0)],
            "release" => vec![r(1, &[]), r(1, &[4]), r(1, &[4, 5]), r(0, &[])],
            "release button" => vec![p(ik::BTN_LEFT, 0), r(0, &[4]), r(0, &[]), p(0, 0)],
            _ => vec![],
        });
    }

    #[test]
    fn ilo4_holds_at_most_six_keys() {
        let evs: Vec<Event> = (0..7).map(|i| key(A + i, true)).chain([key(A + 6, false)]).collect();
        let out = run(Family::Ilo4, &evs);
        assert_eq!(out.len(), 6, "the seventh key and its release send nothing");
        assert_eq!(out[5], ik::key_report(0, &[4, 5, 6, 7, 8, 9]));
    }

    #[test]
    fn avsp_sends_one_packet_per_transition() {
        let k = |h: u8, d: bool| ak::key_packet(h, d);
        let p = |b: u8, w: i16| ak::mouse_packet(511, 191, b, w);
        for family in [Family::Avocent, Family::Idrac8] {
            check(family, |name| match name {
                "plain" => vec![k(4, true), k(4, false)],
                "shift+a" => vec![k(225, true), k(4, true), k(4, false), k(225, false)],
                // Repeats go out as presses of their own.
                "repeat" => vec![k(4, true), k(4, true), k(4, false)],
                "cad" => vec![k(224, true), k(226, true), k(76, true), k(76, false), k(226, false), k(224, false)],
                "chars" => vec![
                    k(4, true), k(4, false),
                    k(225, true), k(4, true), k(4, false), k(225, false),
                    k(225, true), k(0x33, true), k(0x33, false), k(225, false),
                    k(0x28, true), k(0x28, false),
                ],
                "pointer" => vec![p(0, 0), p(ak::BTN_RIGHT, 0), p(0, 0), p(0, 0), p(0, 1), p(0, 0), p(0, 0), p(0, -1), p(0, 0)],
                "release" => vec![k(224, true), k(4, true), k(5, true), k(4, false), k(5, false), k(224, false)],
                "release button" => vec![p(ak::BTN_LEFT, 0), k(4, true), k(4, false), p(0, 0)],
                _ => vec![],
            });
        }
    }

    #[test]
    fn ami_sends_ivtp_reports_with_the_modifier_byte() {
        let k = |h: u8, d: bool, m: u8, s: u32| qk::key_packet(h, d, m, s);
        let p = |b: u8, w: i8, s: u32| qk::mouse_packet(16383, 8191, b, w, s);
        for family in [Family::Quanta, Family::Spx] {
            check(family, |name| match name {
                "plain" => vec![k(4, true, 0, 0), k(4, false, 0, 1)],
                "shift+a" => vec![k(0, false, 2, 0), k(4, true, 2, 1), k(4, false, 2, 2), k(0, false, 0, 3)],
                "repeat" => vec![k(4, true, 0, 0), k(4, false, 0, 1)],
                "cad" => vec![k(0x4c, true, 5, 0), k(0, false, 0, 1)],
                "chars" => vec![
                    k(4, true, 0, 0), k(4, false, 0, 1),
                    k(4, true, 2, 2), k(4, false, 2, 3), k(0, false, 0, 4),
                    k(0x33, true, 2, 5), k(0x33, false, 2, 6), k(0, false, 0, 7),
                    k(0x28, true, 0, 8), k(0x28, false, 0, 9),
                ],
                "pointer" => vec![p(0, 0, 0), p(2, 0, 1), p(0, 0, 2), p(0, 0, 3), p(0, 1, 4), p(0, 0, 5), p(0, -1, 6)],
                "release" => vec![
                    k(0, false, 1, 0), k(4, true, 1, 1), k(5, true, 1, 2),
                    k(4, false, 0, 3), k(5, false, 0, 4), k(224, false, 0, 5),
                ],
                "release button" => vec![p(1, 0, 0), k(4, true, 0, 1), k(4, false, 0, 2), p(0, 0, 3)],
                _ => vec![],
            });
        }
    }

    #[test]
    fn ami_sequence_counts_every_packet() {
        let out = run(Family::Spx, &[key(A, true), ptr(1, 0), key(A, false), Event::Char('b'), ptr(1, 1), Event::CtrlAltDel]);
        let want = vec![
            qk::key_packet(4, true, 0, 0),
            qk::mouse_packet(16383, 8191, 1, 0, 1),
            qk::key_packet(4, false, 0, 2),
            qk::key_packet(5, true, 0, 3),
            qk::key_packet(5, false, 0, 4),
            qk::mouse_packet(16383, 8191, 1, 0, 5),
            qk::mouse_packet(16383, 8191, 1, 1, 6),
            qk::key_packet(0x4c, true, 5, 7),
            qk::key_packet(0, false, 0, 8),
        ];
        assert_eq!(out, want);
    }

    #[test]
    fn modifiers_are_state() {
        // A second down of a held modifier is not news (egui sent only changes).
        for family in [Family::Aten, Family::Idrac9, Family::Ilo4, Family::Avocent, Family::Quanta] {
            let once = run(family, &[key(SHIFT, true)]);
            let twice = run(family, &[key(SHIFT, true), key(SHIFT, true)]);
            assert_eq!(once, twice, "{family:?}");
        }
    }

    /// Decision 5, the one accepted difference: egui used to diff its
    /// modifier state once a frame, so Ctrl and Shift pressed together went out
    /// as ATEN/iDRAC 9's Shift-then-Ctrl, AVSP's Ctrl-then-Shift, or a single
    /// combined AMI/iLO report. As events they are two transitions, Ctrl
    /// first, and the host holds the same set afterwards.
    #[test]
    fn simultaneous_modifiers_go_out_one_at_a_time() {
        let evs = [key(CTRL, true), key(SHIFT, true)];
        let k = |ks: u32| aten::key_event(ks, true).unwrap().to_vec();
        assert_eq!(run(Family::Aten, &evs), vec![k(aten::MOD_CTRL), k(aten::MOD_SHIFT)]);
        assert_eq!(run(Family::Idrac9, &evs), vec![vnc::key_event(0xffe3, true), vnc::key_event(0xffe1, true)]);
        assert_eq!(run(Family::Avocent, &evs), vec![ak::key_packet(224, true), ak::key_packet(225, true)]);
        assert_eq!(run(Family::Ilo4, &evs), vec![ik::key_report(1, &[]), ik::key_report(3, &[])]);
        assert_eq!(run(Family::Quanta, &evs), vec![qk::key_packet(0, false, 1, 0), qk::key_packet(0, false, 3, 1)]);
    }

    #[test]
    fn pointer_clamps_and_maps_the_edges() {
        let mut e = FamilyEncoder::new(Family::Ilo4);
        let mut out = Vec::new();
        e.encode(&Event::Pointer { x: 1.5, y: -0.2, fb: FB, buttons: 0, wheel: 0 }, &mut out);
        assert_eq!(out, vec![ik::mouse(3000, 0, 0, 0)]);
        let mut e = FamilyEncoder::new(Family::Aten);
        let mut out = Vec::new();
        e.encode(&Event::Pointer { x: 1.0, y: 1.0, fb: FB, buttons: BTN_LEFT | BTN_MIDDLE, wheel: 0 }, &mut out);
        assert_eq!(out, vec![aten::pointer_event(1023, 767, 3).to_vec()]);
    }
}
