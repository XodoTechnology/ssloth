//! One ordered input queue per console session.
//!
//! Spike S2 found that input sent from several places at once arrives out of
//! order — Tauri runs concurrent invokes on a pool, and measured up to 28
//! inversions in 400 keys — and a key-up overtaken by its own key-down leaves
//! the key held on a production server. So every producer (key handler,
//! pointer, paste worker, the release on blur) pushes into one channel, and a
//! single consumer thread encodes in arrival order and forwards each packet to
//! the family's `FamilyLink::tx`, whose console thread already sends in order.
//!
//! ReleaseAll travels the same channel, so it lands *behind* input already
//! queued, never ahead of it, and it bumps an epoch. Events carry the epoch
//! they were made in; a key-down stamped before the latest release is stale
//! (it was built before the user looked away) and is dropped. Key-ups go
//! through, since one can only release something. A stale pointer report goes
//! through as a move: its buttons and wheel are stripped, because a report
//! with a button set presses it, and the release has just let every button go.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use super::encoder::{Encode, Event, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT};

/// The record wire the webview sends input in (`ui/src/lib/console/input.ts`).
///
/// 4 bytes: kind, flags (bit 0: down, bit 1: the OS's auto-repeat of a held
/// key), HID usage (page 0x07) as u16 LE. Repeats travel so every front end
/// frames a keystroke alike: the encoder forwards them only to AVSP, whose
/// host never sees a key held (`encoder.rs`).
pub const INPUT_KEY: u8 = 1;
pub const KEY_DOWN: u8 = 1;
pub const KEY_REPEAT: u8 = 2;
/// 4 bytes, the rest zero: every held key and pointer button up.
pub const INPUT_RELEASE_ALL: u8 = 2;
/// 8 bytes: kind, buttons as `PointerEvent.buttons` (1 left, 2 right, 4
/// middle), wheel notches (i8, positive up), 0, x and y as u16 LE in 0..=65535
/// of the screen. Absolute only (Tauri spec, "Console › Input").
pub const INPUT_POINTER: u8 = 3;
/// 4 bytes: kind, 0, epoch as u16 LE — the page's epoch when it built the
/// records after it, which stamps them until the next epoch record. The
/// page's epoch counts its releases: a release record ends the epoch it is
/// stamped with, and the page's next records carry the one after.
pub const INPUT_EPOCH: u8 = 4;

/// One decoded input record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Key { usage: u16, down: bool, repeat: bool },
    ReleaseAll,
    Pointer { buttons: u8, wheel: i8, x: u16, y: u16 },
    Epoch(u16),
}

/// Walks a batch. A record of an unknown kind ends it: its length is unknown,
/// so reading on would take the next record's bytes for a kind.
pub fn records(mut b: &[u8]) -> impl Iterator<Item = Record> + '_ {
    std::iter::from_fn(move || {
        let (rec, len) = match *b {
            [INPUT_KEY, f, lo, hi, ..] => {
                (Record::Key { usage: u16::from_le_bytes([lo, hi]), down: f & KEY_DOWN != 0, repeat: f & KEY_REPEAT != 0 }, 4)
            }
            [INPUT_RELEASE_ALL, _, _, _, ..] => (Record::ReleaseAll, 4),
            [INPUT_POINTER, buttons, wheel, _, x0, x1, y0, y1, ..] => {
                (Record::Pointer { buttons, wheel: wheel as i8, x: u16::from_le_bytes([x0, x1]), y: u16::from_le_bytes([y0, y1]) }, 8)
            }
            [INPUT_EPOCH, _, lo, hi, ..] => (Record::Epoch(u16::from_le_bytes([lo, hi])), 4),
            _ => return None,
        };
        b = &b[len..];
        Some(rec)
    })
}

/// The gap after each packet of a pasted character. BMCs forward HID reports
/// to the host's USB stack at their own pace and drop what arrives faster; a
/// key needs its own report. Pacing here, behind the one consumer, keeps a
/// paste's Shift, key and release apart even when the producer pushes them
/// back to back (moved from the egui app's typing worker, unchanged).
pub const CHAR_PACKET_GAP: std::time::Duration = std::time::Duration::from_millis(12);

enum Msg {
    Event(u32, Event),
    /// Answered once everything queued before it has gone to `tx`.
    Flush(Sender<()>),
}

/// A handle on a session's queue. Clones share the queue, so the paste
/// worker can type through the same channel as the key handler.
#[derive(Clone)]
pub struct InputQueue {
    tx: Sender<Msg>,
    epoch: Arc<AtomicU32>,
    /// The page's own epoch, as far as its records have told us: the wire
    /// carries the page's count of its releases, not ours. None until a new
    /// page's first epoch record, which is taken as it comes: compared with
    /// a guess, a page already at 32768 or more would read as older.
    page_epoch: Arc<Mutex<Option<u16>>>,
}

impl InputQueue {
    /// Start the consumer: it encodes each event with `encoder` and forwards
    /// the packets to `tx`. It ends once every handle is dropped, or at the
    /// first send after the family's end of `tx` has gone.
    pub fn spawn(encoder: Box<dyn Encode>, tx: Sender<Vec<u8>>) -> InputQueue {
        Self::spawn_joinable(encoder, tx).0
    }

    /// [`spawn`](Self::spawn), keeping the consumer's handle.
    pub fn spawn_joinable(mut encoder: Box<dyn Encode>, tx: Sender<Vec<u8>>) -> (InputQueue, JoinHandle<()>) {
        let (qtx, qrx) = mpsc::channel::<Msg>();
        let handle = std::thread::Builder::new()
            .name("input-queue".into())
            .spawn(move || {
                let mut released = 0u32;
                let mut out = Vec::new();
                while let Ok(msg) = qrx.recv() {
                    let (stamp, ev) = match msg {
                        Msg::Event(stamp, ev) => (stamp, ev),
                        Msg::Flush(done) => {
                            let _ = done.send(());
                            continue;
                        }
                    };
                    let ev = match ev {
                        Event::ReleaseAll => {
                            released = released.max(stamp);
                            ev
                        }
                        Event::Key { down: true, .. } if stamp < released => continue,
                        Event::Pointer { x, y, fb, .. } if stamp < released => Event::Pointer { x, y, fb, buttons: 0, wheel: 0 },
                        _ => ev,
                    };
                    encoder.encode(&ev, &mut out);
                    let paced = matches!(ev, Event::Char(_));
                    for p in out.drain(..) {
                        if tx.send(p).is_err() {
                            return;
                        }
                        if paced {
                            std::thread::sleep(CHAR_PACKET_GAP);
                        }
                    }
                }
            })
            .expect("spawn input queue");
        (InputQueue { tx: qtx, epoch: Arc::new(AtomicU32::new(0)), page_epoch: Arc::new(Mutex::new(None)) }, handle)
    }

    /// The current epoch: the number of releases queued so far.
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Queue an event made now.
    pub fn push(&self, ev: Event) {
        self.push_at(self.epoch(), ev);
    }

    /// Queue an event made in `epoch`. A key-down from before the latest
    /// release is dropped when it reaches the front, and a pointer report
    /// from then loses its buttons and wheel.
    pub fn push_at(&self, epoch: u32, ev: Event) {
        if matches!(ev, Event::ReleaseAll) {
            self.release_all();
        } else {
            let _ = self.tx.send(Msg::Event(epoch, ev));
        }
    }

    /// Block until everything queued so far has been encoded and handed to
    /// the family's `tx` (or the queue has ended).
    pub fn flush(&self) {
        let (done, wait) = mpsc::channel();
        if self.tx.send(Msg::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Release every held key and pointer button, behind whatever is
    /// already queued.
    pub fn release_all(&self) {
        let e = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.tx.send(Msg::Event(e, Event::ReleaseAll));
    }

    /// A new page may be attached (a reload, a remounted tab), whose epochs
    /// start again from 0: forget the old page's, and take the next epoch
    /// record as the page's own. Every page batch opens with one.
    pub fn new_page(&self) {
        *self.page_epoch.lock().unwrap() = None;
    }

    /// Queue a batch of the webview's records, for a framebuffer of `fb`.
    /// A key-down the page made in an epoch it has since released is stale
    /// and dropped here, and a pointer report from then goes as a move;
    /// everything else goes through in record order.
    pub fn push_records(&self, body: &[u8], fb: (usize, usize)) {
        let mut page = self.page_epoch.lock().unwrap();
        // Wrapping comparison: the page's u16 epoch may wrap.
        let older = |a: u16, b: u16| (a.wrapping_sub(b) as i16) < 0;
        // Records before any epoch record were made now.
        let mut stamp = *page;
        let stale = |stamp: Option<u16>, page: Option<u16>| matches!((stamp, page), (Some(s), Some(p)) if older(s, p));
        for rec in records(body) {
            match rec {
                Record::Epoch(e) => {
                    stamp = Some(e);
                    if page.is_none_or(|p| older(p, e)) {
                        *page = Some(e);
                    }
                }
                Record::ReleaseAll => {
                    self.release_all();
                    let next = stamp.unwrap_or(0).wrapping_add(1);
                    if page.is_none_or(|p| older(p, next)) {
                        *page = Some(next);
                    }
                }
                Record::Key { usage, down, repeat } => {
                    if down && stale(stamp, *page) {
                        continue;
                    }
                    self.push(Event::Key { usage, down, repeat });
                }
                Record::Pointer { buttons, wheel, x, y } => {
                    // PointerEvent.buttons order (L, R, M) to RFB's (L, M, R).
                    let mut b = (if buttons & 1 != 0 { BTN_LEFT } else { 0 })
                        | (if buttons & 2 != 0 { BTN_RIGHT } else { 0 })
                        | (if buttons & 4 != 0 { BTN_MIDDLE } else { 0 });
                    let mut wheel = wheel;
                    if stale(stamp, *page) {
                        (b, wheel) = (0, 0);
                    }
                    let f = |v: u16| f32::from(v) / 65535.0;
                    self.push(Event::Pointer { x: f(x), y: f(y), fb, buttons: b, wheel });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;

    /// Records each event it is given, one packet per event, so the sink's
    /// order is the encoder's order.
    struct Log;
    impl Encode for Log {
        fn encode(&mut self, ev: &Event, out: &mut Vec<Vec<u8>>) {
            out.push(format!("{ev:?}").into_bytes());
        }
    }

    fn queue() -> (InputQueue, JoinHandle<()>, Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let (q, h) = InputQueue::spawn_joinable(Box::new(Log), tx);
        (q, h, rx)
    }

    /// Everything the sink got, once every handle is gone and the thread ended.
    fn drain(q: InputQueue, h: JoinHandle<()>, rx: Receiver<Vec<u8>>) -> Vec<String> {
        drop(q);
        h.join().unwrap();
        rx.try_iter().map(|p| String::from_utf8(p).unwrap()).collect()
    }

    fn key(usage: u16, down: bool) -> Event {
        Event::Key { usage, down, repeat: false }
    }
    fn s(ev: Event) -> String {
        format!("{ev:?}")
    }

    #[test]
    fn records_decode_in_order_and_stop_at_an_unknown_kind() {
        let b = [
            INPUT_EPOCH, 0, 0x34, 0x12,
            INPUT_KEY, 1, 0x04, 0,
            INPUT_POINTER, 1, 0xFF, 0, 0x00, 0x80, 0xFF, 0xFF,
            INPUT_RELEASE_ALL, 0, 0, 0,
            9, INPUT_KEY, 1, 0x05,
        ];
        let got: Vec<_> = records(&b).collect();
        assert_eq!(
            got,
            [
                Record::Epoch(0x1234),
                Record::Key { usage: 0x04, down: true, repeat: false },
                Record::Pointer { buttons: 1, wheel: -1, x: 0x8000, y: 0xFFFF },
                Record::ReleaseAll,
            ]
        );
    }

    #[test]
    fn interleaved_input_arrives_in_order() {
        let (q, h, rx) = queue();
        let p = Event::Pointer { x: 0.5, y: 0.5, fb: (10, 10), buttons: 1, wheel: 0 };
        q.push(key(4, true));
        q.push(p);
        q.push(key(4, false));
        q.release_all();
        q.push(Event::Char('x'));
        assert_eq!(drain(q, h, rx), [s(key(4, true)), s(p), s(key(4, false)), s(Event::ReleaseAll), s(Event::Char('x'))]);
    }

    #[test]
    fn many_producers_never_reorder_one_producers_events() {
        let (q, h, rx) = queue();
        let threads: Vec<_> = (0..4u16)
            .map(|t| {
                let q = q.clone();
                std::thread::spawn(move || {
                    for i in 0..200u16 {
                        q.push(key(t * 1000 + i, false));
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        let got = drain(q, h, rx);
        assert_eq!(got.len(), 800);
        for t in 0..4u16 {
            let mine: Vec<String> = got.iter().filter(|g| {
                (0..200).any(|i| **g == s(key(t * 1000 + i, false)))
            }).cloned().collect();
            let want: Vec<String> = (0..200).map(|i| s(key(t * 1000 + i, false))).collect();
            assert_eq!(mine, want, "producer {t}");
        }
    }

    #[test]
    fn release_lands_behind_pending_input() {
        let (tx, rx) = mpsc::channel();
        let (q, h) = InputQueue::spawn_joinable(Box::new(crate::input::FamilyEncoder::new(crate::families::Family::Avocent)), tx);
        q.push(key(4, true));
        q.release_all();
        drop(q);
        h.join().unwrap();
        let got: Vec<Vec<u8>> = rx.try_iter().collect();
        use crate::families::avocent::kvm::key_packet;
        assert_eq!(got, [key_packet(4, true), key_packet(4, false)]);
    }

    #[test]
    fn stale_down_is_dropped() {
        let (q, h, rx) = queue();
        let before = q.epoch();
        q.release_all();
        q.push_at(before, key(4, true));
        q.push_at(before, key(4, false));
        q.push(key(5, true));
        assert_eq!(drain(q, h, rx), [s(Event::ReleaseAll), s(key(4, false)), s(key(5, true))]);
    }

    #[test]
    fn a_page_batch_from_before_its_release_loses_its_downs() {
        let (q, h, rx) = queue();
        // Epoch 0: A down. Then the page releases, ending epoch 0, and a late
        // batch still stamped 0 arrives with B down and A up.
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_KEY, 1, 4, 0], (10, 10));
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_RELEASE_ALL, 0, 0, 0], (10, 10));
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_KEY, 1, 5, 0, INPUT_KEY, 0, 4, 0], (10, 10));
        q.push_records(&[INPUT_EPOCH, 0, 1, 0, INPUT_KEY, 1, 6, 0], (10, 10));
        assert_eq!(drain(q, h, rx), [s(key(4, true)), s(Event::ReleaseAll), s(key(4, false)), s(key(6, true))]);
    }

    #[test]
    fn page_pointer_buttons_and_position_convert() {
        let (q, h, rx) = queue();
        // Right and middle held (PointerEvent 2|4), wheel down, bottom-right.
        q.push_records(&[INPUT_POINTER, 6, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF], (800, 600));
        let want = Event::Pointer { x: 1.0, y: 1.0, fb: (800, 600), buttons: BTN_RIGHT | BTN_MIDDLE, wheel: -1 };
        assert_eq!(drain(q, h, rx), [s(want)]);
    }

    #[test]
    fn repeats_travel_the_record_wire() {
        let (q, h, rx) = queue();
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_KEY, KEY_DOWN, 4, 0, INPUT_KEY, KEY_DOWN | KEY_REPEAT, 4, 0, INPUT_KEY, 0, 4, 0], (10, 10));
        let rep = Event::Key { usage: 4, down: true, repeat: true };
        assert_eq!(drain(q, h, rx), [s(key(4, true)), s(rep), s(key(4, false))]);
    }

    #[test]
    fn a_stale_pointer_report_is_only_a_move() {
        let (q, h, rx) = queue();
        let p = |buttons: u8, wheel: i8| Event::Pointer { x: 0.5, y: 0.5, fb: (10, 10), buttons, wheel };
        let before = q.epoch();
        q.release_all();
        q.push_at(before, p(BTN_LEFT, 1));
        q.push(p(BTN_LEFT, 0));
        // The page's own: a click from epoch 0 arriving after its release.
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_RELEASE_ALL, 0, 0, 0], (10, 10));
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_POINTER, 1, 1, 0, 0, 0, 0, 0], (10, 10));
        let corner = Event::Pointer { x: 0.0, y: 0.0, fb: (10, 10), buttons: 0, wheel: 0 };
        assert_eq!(drain(q, h, rx), [s(Event::ReleaseAll), s(p(0, 0)), s(p(BTN_LEFT, 0)), s(Event::ReleaseAll), s(corner)]);
    }

    #[test]
    fn a_new_page_takes_its_first_epoch_as_it_comes() {
        let (q, h, rx) = queue();
        // A page reconnecting its frame socket at epoch 40000, more than
        // half the u16 range from 0: compared with 0 it would read as older.
        q.new_page();
        q.push_records(&[INPUT_EPOCH, 0, 0x40, 0x9c, INPUT_KEY, 1, 4, 0], (10, 10));
        assert_eq!(drain(q, h, rx), [s(key(4, true))]);
    }

    #[test]
    fn a_new_page_starts_its_epochs_again() {
        let (q, h, rx) = queue();
        q.push_records(&[INPUT_EPOCH, 0, 7, 0, INPUT_RELEASE_ALL, 0, 0, 0], (10, 10));
        q.new_page();
        q.push_records(&[INPUT_EPOCH, 0, 0, 0, INPUT_KEY, 1, 4, 0], (10, 10));
        assert_eq!(drain(q, h, rx), [s(Event::ReleaseAll), s(key(4, true))]);
    }

    #[test]
    fn flush_waits_for_everything_before_it() {
        let (q, h, rx) = queue();
        q.push(key(4, true));
        q.release_all();
        q.flush();
        let got: Vec<String> = rx.try_iter().map(|p| String::from_utf8(p).unwrap()).collect();
        assert_eq!(got, [s(key(4, true)), s(Event::ReleaseAll)]);
        drop(q);
        h.join().unwrap();
    }

    #[test]
    fn queue_ends_when_tx_drops() {
        let (q, h, rx) = queue();
        drop(rx);
        // The consumer learns the family's end has gone at its next send.
        q.push(key(4, true));
        h.join().unwrap();
        // The handle outlives the thread; pushing or flushing is harmless.
        q.push(key(4, false));
        q.flush();
    }
}
