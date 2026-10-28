//! HP "DVC" video decoder — the codec behind iLO's Integrated Remote Console.
//!
//! A faithful port of the decoder iLO 4 serves to its own HTML5 console
//! (`js/state.js` + `js/cache.js`, saved under `~/.config/smc-ikvm/ilo4-ref/`).
//!
//! Unlike the JPEG-family AST2100 codec, this is a *bit*-oriented state machine:
//! a 49-entry table where each state declares how many bits to consume, which
//! state each outcome leads to, and an action. Pixels are emitted into a 16x16
//! (or 16x8) block which is blitted once full; colours come either as literals
//! or as indices into a 17-entry move-to-front LRU cache whose index width
//! shrinks and grows with its occupancy.
//!
//! Colour words are 16-bit: bit 0 is a "used since last prune" alpha flag and
//! the rest packs blue/green/red at `bpc` bits each (bpc 2..5, negotiated in the
//! stream header), i.e. RGBA5551 at the usual bpc=5.
//!
//! Bit fields are read LSB-first into an accumulator and then bit-reversed
//! within their width, so `getbit` mirrors the reference's reversal exactly.

use crate::ast2100;

// ---------- state ids (constants.js) ----------
const RESET: usize = 0;
const START: usize = 1;
const PIXELS: usize = 2;
const PIXLRU1: usize = 3;
const PIXLRU0: usize = 4;
const PIXCODE1: usize = 5;
const PIXCODE2: usize = 6;
const PIXCODE3: usize = 7;
const PIXGREY: usize = 8;
const PIXRGBR: usize = 9;
const PIXRPT: usize = 10;
const PIXRPT1: usize = 11;
const PIXRPTSTD1: usize = 12;
const PIXRPTSTD2: usize = 13;
const PIXRPTNSTD: usize = 14;
const CMD: usize = 15;
const CMD0: usize = 16;
const MOVEXY0: usize = 17;
const EXTCMD: usize = 18;
const CMDX: usize = 19;
const MOVESHORTX: usize = 20;
const MOVELONGX: usize = 21;
const BLKRPT: usize = 22;
const EXTCMD1: usize = 23;
const FIRMWARE: usize = 24;
const EXTCMD2: usize = 25;
const MODE0: usize = 26;
const TIMEOUT: usize = 27;
const BLKRPT1: usize = 28;
const BLKRPTSTD: usize = 29;
const BLKRPTNSTD: usize = 30;
const PIXFAN: usize = 31;
const PIXCODE4: usize = 32;
const PIXDUP: usize = 33;
const BLKDUP: usize = 34;
const PIXCODE: usize = 35;
const PIXSPEC: usize = 36;
const EXIT: usize = 37;
const LATCHED: usize = 38;
const MOVEXY1: usize = 39;
const MODE1: usize = 40;
const PIXRGBG: usize = 41;
const PIXRGBB: usize = 42;
const HUNT: usize = 43;
const PRINT0: usize = 44;
const PRINT1: usize = 45;
const CORP: usize = 46;
const MODE2: usize = 47;
const PIXRGB: usize = 48;

const NSTATES: usize = 49;
const CACHE_SIZE: usize = 17;
const AMASK: u16 = 1;

/// Per-state action.
#[derive(Clone, Copy, PartialEq, Eq)]
enum F {
    Reset, NoOp, PixCodeX, PixGrey, PixRgbR, PixRgbG, PixRgbB, PixRgb,
    PixRptStd1, PixRptStd2, PixRptNStd, PixDup, MoveShortX, MoveLongX,
    MoveXY0, MoveXY1, Mode1, Mode2, BlkDup, BlkRptStd, BlkRptNStd,
    Firmware, Corp, Timeout, Print0, Print1, Latched, Hunt, Exit, PixCode,
}

#[derive(Clone, Copy)]
struct Entry {
    bits: i32,
    next0: usize,
    next1: usize,
    func: F,
}

const fn e(bits: i32, next0: usize, next1: usize, func: F) -> Entry {
    Entry { bits, next0, next1, func }
}

/// The reference table, in state-id order.
const TABLE: [Entry; NSTATES] = [
    e(0, START, START, F::Reset),                   // RESET
    e(1, PIXELS, CMD, F::NoOp),                     // START
    e(1, PIXFAN, PIXLRU1, F::NoOp),                 // PIXELS
    e(1, PIXELS, PIXRPT1, F::PixCodeX),             // PIXLRU1
    e(1, PIXELS, PIXRPT1, F::PixCodeX),             // PIXLRU0
    e(1, PIXRPT, PIXRPT, F::PixCodeX),              // PIXCODE1
    e(2, PIXRPT, PIXRPT, F::PixCodeX),              // PIXCODE2
    e(3, PIXRPT, PIXRPT, F::PixCodeX),              // PIXCODE3
    e(4, PIXRPT, PIXRPT, F::PixGrey),               // PIXGREY
    e(4, PIXRGBG, PIXRGBG, F::PixRgbR),             // PIXRGBR
    e(1, PIXELS, PIXRPT1, F::NoOp),                 // PIXRPT
    e(1, PIXDUP, PIXRPTSTD1, F::NoOp),              // PIXRPT1
    e(3, PIXELS, PIXELS, F::PixRptStd1),            // PIXRPTSTD1
    e(3, PIXELS, PIXELS, F::PixRptStd2),            // PIXRPTSTD2
    e(8, PIXELS, PIXELS, F::PixRptNStd),            // PIXRPTNSTD
    e(1, CMD0, MOVEXY0, F::NoOp),                   // CMD
    e(1, CMDX, EXTCMD, F::NoOp),                    // CMD0
    e(7, MOVEXY1, MOVEXY1, F::MoveXY0),             // MOVEXY0
    e(1, BLKRPT, EXTCMD1, F::NoOp),                 // EXTCMD
    e(1, MOVESHORTX, MOVELONGX, F::NoOp),           // CMDX
    e(3, START, START, F::MoveShortX),              // MOVESHORTX
    e(7, START, START, F::MoveLongX),               // MOVELONGX
    e(1, BLKDUP, BLKRPT1, F::NoOp),                 // BLKRPT
    e(1, EXTCMD2, FIRMWARE, F::NoOp),               // EXTCMD1
    e(8, CORP, CORP, F::Firmware),                  // FIRMWARE
    e(1, MODE0, TIMEOUT, F::NoOp),                  // EXTCMD2
    e(7, MODE1, MODE1, F::MoveXY0),                 // MODE0
    e(0, START, START, F::Timeout),                 // TIMEOUT
    e(1, BLKRPTSTD, BLKRPTNSTD, F::NoOp),           // BLKRPT1
    e(3, START, START, F::BlkRptStd),               // BLKRPTSTD
    e(7, START, START, F::BlkRptNStd),              // BLKRPTNSTD
    e(1, PIXSPEC, PIXCODE, F::NoOp),                // PIXFAN
    e(4, PIXRPT, PIXRPT, F::PixCodeX),              // PIXCODE4
    e(0, PIXELS, PIXELS, F::PixDup),                // PIXDUP
    e(0, START, START, F::BlkDup),                  // BLKDUP
    e(0, PIXCODE, PIXCODE, F::PixCode),             // PIXCODE
    e(1, PIXGREY, PIXRGB, F::NoOp),                 // PIXSPEC
    e(0, EXIT, EXIT, F::Exit),                      // EXIT
    e(1, LATCHED, LATCHED, F::Latched),             // LATCHED
    e(7, START, START, F::MoveXY1),                 // MOVEXY1
    e(7, MODE2, MODE2, F::Mode1),                   // MODE1
    e(4, PIXRGBB, PIXRGBB, F::PixRgbG),             // PIXRGBG
    e(4, PIXRPT, PIXRPT, F::PixRgbB),               // PIXRGBB
    e(1, HUNT, RESET, F::Hunt),                     // HUNT
    e(8, PRINT1, PRINT1, F::Print0),                // PRINT0
    e(8, PRINT1, PRINT1, F::Print1),                // PRINT1
    e(1, START, FIRMWARE, F::Corp),                 // CORP
    e(4, START, START, F::Mode2),                   // MODE2
    e(12, PIXRPT, PIXRPT, F::PixRgb),               // PIXRGB
];

/// Side-effects the caller must act on (they reach the console channel or GUI).
#[derive(Clone, Debug)]
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub enum Event {
    SetSize(usize, usize),
    Clear,
    Text(i32, String),
    Power(bool),
    /// The stream asked us to acknowledge it (keeps video flowing).
    SendAck,
    /// The decoder lost sync and wants a fresh full frame.
    Refresh,
    Exit,
    License { irc: bool, playback: bool, murc: bool },
    /// A URL-mounted virtual device is attached (floppy vs CD).
    VmUrlConnected { floppy: bool },
}

// ---------- LRU colour cache ----------
struct ColorCache {
    active: usize,
    pixcode: usize,
    element: [u16; CACHE_SIZE],
}

/// Cache occupancy decides how many bits a colour index costs.
fn code_for(active: usize) -> usize {
    if active < 2 { LATCHED }
    else if active == 2 { PIXLRU0 }
    else if active == 3 { PIXCODE1 }
    else if active < 6 { PIXCODE2 }
    else if active < 10 { PIXCODE3 }
    else { PIXCODE4 }
}

impl ColorCache {
    fn new() -> Self {
        ColorCache { active: 0, pixcode: LATCHED, element: [0; CACHE_SIZE] }
    }

    fn reset(&mut self) {
        self.element[..self.active].fill(0);
        self.active = 0;
        self.pixcode = LATCHED;
    }

    /// Insert `color` at the front (move-to-front if already present).
    fn lru(&mut self, color: u16) {
        let mut active = self.active;
        let color = color | AMASK;
        // The reference searches backwards over the live entries.
        let mut code: i64 = -1;
        for i in (0..active).rev() {
            if self.element[i] == color { code = i as i64; break; }
        }
        if code == -1 {
            if active < CACHE_SIZE {
                active += 1;
                // copyWithin(1, 0, active), which JS clamps to the array end.
                let n = active.min(CACHE_SIZE - 1);
                self.element.copy_within(0..n, 1);
                self.element[0] = color;
                self.pixcode = code_for(active);
                self.active = active;
                return;
            }
            code = active as i64;
        }
        if code > 0 {
            let n = active.min(CACHE_SIZE - 1);
            self.element.copy_within(0..n, 1);
            self.element[0] = color;
        }
    }

    /// Colour at index `code`, moved to the front. 0 means "out of range".
    fn find(&mut self, code: usize) -> u16 {
        if code > self.active || code >= CACHE_SIZE {
            return 0;
        }
        let color = self.element[code] | AMASK;
        if code > 0 {
            let n = code.min(CACHE_SIZE - 1);
            self.element.copy_within(0..n, 1);
        }
        self.element[0] = color | AMASK;
        color
    }

    /// Drop entries not referenced since the previous prune; clear the marks.
    fn prune(&mut self) {
        let active = self.active;
        let mut t = 0usize;
        for i in 0..active {
            if self.element[i] & AMASK != 0 {
                self.element[t] = self.element[i] & !AMASK;
                t += 1;
            }
        }
        self.element[active..].fill(0);
        self.active = t;
        self.pixcode = code_for(t);
    }
}

// ---------- decoder ----------
pub struct Dvc {
    table: [Entry; NSTATES],
    decoder_state: usize,
    next_state: usize,

    zero_count: u32,
    count_bytes: u64,
    ib_acc: u32,
    ib_bcnt: i32,

    /// Screen geometry in blocks, plus the sub-block height remainder.
    sizex: i32,
    sizey: i32,
    sizey1: i32,
    blockwidth: usize,
    blockheight: usize,

    newx: i32,
    newy: i32,
    lastx: i32,
    lasty: i32,

    pixels: Vec<u16>,
    pixel_count: usize,
    last_color: u16,
    block_count: u64,

    fatal_count: u64,
    timeout_count: i64,

    cmd_idx: usize,
    cmd_buf: Vec<u8>,
    cmd_last: u8,
    print_chan: i32,
    print_buf: Vec<u8>,

    cache: ColorCache,

    /// Colour unpacking, derived from the negotiated bits-per-colour.
    cscale: u32,
    bmask: u32,
    scale: [u8; 32],

    /// Stream header facts worth surfacing.
    pub cipher: &'static str,
    pub licensed_irc: bool,
    pub half_height_capable: bool,

    events: Vec<Event>,
}

impl Dvc {
    pub fn new() -> Self {
        let mut d = Dvc {
            table: TABLE,
            decoder_state: RESET,
            next_state: RESET,
            zero_count: 0,
            count_bytes: 0,
            ib_acc: 0,
            ib_bcnt: 0,
            sizex: 0,
            sizey: 0,
            sizey1: 0,
            blockwidth: 16,
            blockheight: 16,
            newx: 0,
            newy: 0,
            lastx: 0,
            lasty: 0,
            pixels: vec![0; 16 * 16],
            pixel_count: 0,
            last_color: 0,
            block_count: 0,
            fatal_count: 0,
            timeout_count: -1,
            cmd_idx: 0,
            cmd_buf: Vec::new(),
            cmd_last: 0,
            print_chan: 0,
            print_buf: Vec::new(),
            cache: ColorCache::new(),
            cscale: 5,
            bmask: 31,
            scale: [0; 32],
            cipher: "",
            licensed_irc: false,
            half_height_capable: false,
            events: Vec::new(),
        };
        d.set_bitspercolor(0); // default 5 bits per colour
        d
    }

    /// Feed one WebSocket message. Returns the side-effects it produced.
    pub fn process(&mut self, data: &[u8], fb: &mut ast2100::Decoder) -> Vec<Event> {
        fb.bytes_in += data.len() as u64;
        let blocks_before = self.block_count;
        'outer: for &byte in data {
            self.addbits(byte);
            loop {
                if self.decoder_state == EXIT {
                    break;
                }
                let entry = self.table[self.decoder_state];
                if entry.bits > self.ib_bcnt {
                    break;
                }
                let code = self.getbit(entry.bits);
                self.next_state = if code != 0 { entry.next1 } else { entry.next0 };
                self.run(entry.func, code, fb);
                if self.next_state == PIXELS
                    && self.pixel_count == self.blockwidth * self.blockheight
                {
                    self.next_block(1, fb);
                    self.cache.prune();
                    self.table[PIXFAN].next1 = self.cache.pixcode;
                }
                // The reference bails out of the whole message on a self-loop
                // that isn't one of the three intentionally looping states.
                if self.decoder_state == self.next_state
                    && self.decoder_state != PRINT1
                    && self.decoder_state != LATCHED
                    && self.decoder_state != HUNT
                {
                    break 'outer;
                }
                self.decoder_state = self.next_state;
            }
        }
        if self.block_count > blocks_before {
            fb.frames += 1;
        }
        std::mem::take(&mut self.events)
    }

    // ---------- bit plumbing ----------

    fn addbits(&mut self, bits: u8) {
        self.zero_count += trail_zeros(bits);
        self.count_bytes = self.count_bytes.wrapping_add(1);
        self.ib_acc |= (bits as u32).wrapping_shl(self.ib_bcnt as u32);
        self.ib_bcnt += 8;
        // A long zero run can't occur in a valid stream: resynchronise.
        if self.zero_count > 30 {
            self.decoder_state = HUNT;
            self.next_state = HUNT;
            self.ib_bcnt = 8;
            return;
        }
        if bits != 0 {
            self.zero_count = lead_zeros(bits);
        }
    }

    /// Consume `length` bits and return them bit-reversed within that width.
    fn getbit(&mut self, length: i32) -> u32 {
        if length == 0 {
            return 0;
        }
        let mut temp = self.ib_acc & ((1u32 << length) - 1);
        self.ib_bcnt -= length;
        self.ib_acc >>= length;
        temp = ((temp >> 8) & 0x00FF) | ((temp << 8) & 0xFF00);
        temp = ((temp >> 4) & 0x0F0F) | ((temp << 4) & 0xF0F0);
        temp = ((temp >> 2) & 0x3333) | ((temp << 2) & 0xCCCC);
        temp = ((temp >> 1) & 0x5555) | ((temp << 1) & 0xAAAA);
        temp >> (16 - length)
    }

    // ---------- actions ----------

    fn run(&mut self, f: F, code: u32, fb: &mut ast2100::Decoder) {
        match f {
            F::NoOp => {}
            F::Reset => {
                self.cache.reset();
                self.pixel_count = 0;
                self.block_count = 0;
                self.lastx = 0;
                self.lasty = 0;
                self.fatal_count = 0;
                self.timeout_count = -1;
                self.table[PIXFAN].next1 = PIXCODE;
            }
            F::PixCode => self.next_state = self.cache.pixcode,
            F::PixCodeX => {
                let mut c = code as usize;
                if self.cache.active == 1 {
                    c = 0;
                } else if self.decoder_state == PIXLRU0 {
                    c = 0;
                } else if self.decoder_state == PIXLRU1 {
                    c = 1;
                } else if c != 0 {
                    c += 1;
                }
                let color = self.cache.find(c);
                if color != 0 {
                    self.store_pixel(color, 1);
                } else {
                    self.next_state = LATCHED;
                }
            }
            F::PixGrey => {
                let cs = self.cscale;
                let color = (((code << (2 * cs)) | (code << cs) | code) << 1 | 1) as u16;
                self.cache.lru(color);
                self.table[PIXFAN].next1 = self.cache.pixcode;
                self.store_pixel(color, 1);
            }
            F::PixRgb => {
                let color = ((code << 1) | 1) as u16;
                self.cache.lru(color);
                self.table[PIXFAN].next1 = self.cache.pixcode;
                self.store_pixel(color, 1);
            }
            // The literal-RGB triple states are unreachable from this table
            // (nothing transitions into PIXRGBR); kept for table fidelity.
            F::PixRgbR | F::PixRgbG => {}
            F::PixRgbB => {
                let color = code as u16;
                self.cache.lru(color);
                self.table[PIXFAN].next1 = self.cache.pixcode;
                self.store_pixel(color, 1);
            }
            F::PixRptStd1 => {
                if code == 7 {
                    self.next_state = PIXRPTNSTD;
                } else if code == 6 {
                    self.next_state = PIXRPTSTD2;
                } else {
                    self.store_pixel(self.last_color, code as usize + 2);
                }
            }
            F::PixRptStd2 => self.store_pixel(self.last_color, code as usize + 8),
            F::PixRptNStd => self.store_pixel(self.last_color, code as usize),
            F::PixDup => self.store_pixel(self.last_color, 1),
            F::MoveShortX => self.lastx += code as i32 + 1,
            F::MoveLongX => self.lastx = code as i32,
            F::MoveXY0 => self.newx = code as i32,
            F::MoveXY1 => {
                self.newy = code as i32;
                self.lastx = self.newx;
                self.lasty = self.newy;
            }
            F::Mode1 => {
                let mut c = code as i32;
                if self.newx == 0 || c == 0 {
                    self.newx = 50;
                    c = 38;
                    self.events.push(Event::Clear);
                }
                self.sizex = self.newx;
                self.sizey = c;
            }
            F::Mode2 => {
                self.lastx = 0;
                self.lasty = 0;
                self.pixel_count = 0;
                self.sizey1 = code as i32;
                let x = 16 * self.sizex;
                let y = 16 * self.sizey + self.sizey1;
                self.cache.reset();
                if x > 0 && y > 0 && x <= 4096 && y <= 4096 {
                    let (w, h) = (x as usize, y as usize);
                    if fb.width != w || fb.height != h {
                        fb.resize(w, h);
                        self.events.push(Event::SetSize(w, h));
                    }
                }
                self.set_halfheight(x > 1616);
            }
            F::BlkDup => self.next_block(1, fb),
            F::BlkRptStd => self.next_block(code as usize + 2, fb),
            F::BlkRptNStd => self.next_block(code as usize, fb),
            F::Firmware => {
                if self.cmd_idx == 0 {
                    self.cmd_buf.clear();
                } else {
                    self.cmd_buf.push(self.cmd_last);
                }
                self.cmd_idx += 1;
                self.cmd_last = code as u8;
            }
            F::Corp => {
                if code == 0 {
                    self.corp();
                    self.cmd_idx = 0;
                }
            }
            F::Timeout => {
                if self.timeout_count == self.count_bytes as i64 - 1 {
                    self.next_state = LATCHED;
                }
                self.getbit(self.ib_bcnt & 7); // re-align to a byte boundary
                self.timeout_count = self.count_bytes as i64;
            }
            F::Print0 => {
                self.print_chan = code as i32;
                self.print_buf.clear();
            }
            F::Print1 => {
                if code != 0 {
                    self.print_buf.push(code as u8);
                } else {
                    let s = String::from_utf8_lossy(&self.print_buf).into_owned();
                    self.events.push(Event::Text(self.print_chan, s));
                    self.next_state = START;
                }
            }
            F::Latched => {
                // Lost sync: nudge the BMC for a fresh full frame, then back off.
                if self.fatal_count == 40 {
                    self.events.push(Event::Refresh);
                }
                self.fatal_count += 1;
                if self.fatal_count == 120_000 {
                    self.events.push(Event::Refresh);
                } else if self.fatal_count == 12_000_000 {
                    self.fatal_count = 41;
                    self.events.push(Event::Refresh);
                }
            }
            F::Hunt => {
                if self.next_state != self.decoder_state {
                    self.ib_bcnt = 0;
                    self.ib_acc = 0;
                    self.zero_count = 0;
                    self.count_bytes = 0;
                }
            }
            F::Exit => self.events.push(Event::Exit),
        }
    }

    /// Out-of-band command, terminated by a 0 bit in the CORP state. The final
    /// byte read is the opcode; any earlier bytes are its arguments.
    fn corp(&mut self) {
        match self.cmd_last {
            1 => self.next_state = EXIT,
            2 => self.next_state = PRINT0,
            4 => self.events.push(Event::Power(true)),
            5 => {
                self.newx = 50;
                self.newy = 38;
                self.events.push(Event::Clear);
                self.events.push(Event::Power(false));
            }
            6 => {
                self.events.push(Event::Clear);
                self.events.push(Event::Text(-1, "Video Suspended".into()));
            }
            9 => {
                let n = self.ib_bcnt & 7;
                if n != 0 {
                    self.getbit(n);
                }
            }
            10 => {
                self.events.push(Event::Clear);
                self.events.push(Event::Text(-1, "Session acquired by another user".into()));
            }
            11 => {
                let b = self.cmd_buf.first().copied().unwrap_or(0);
                self.set_bitspercolor(b);
            }
            13 => self.process_header(),
            16 => self.events.push(Event::SendAck),
            _ => {} // 3, 7, 8, 12, 128: nothing to do
        }
    }

    /// Stream header: [bits-per-colour, encryption, licence bits, flags].
    fn process_header(&mut self) {
        let mut h = [0u8; 4];
        for (i, b) in self.cmd_buf.iter().take(4).enumerate() {
            h[i] = *b;
        }
        let g = |i: usize| h[i];
        self.set_bitspercolor(g(0));
        self.cipher = match g(1) {
            1 => "RC4",
            2 => "AES",
            3 => "AES-256",
            _ => "",
        };
        let lic = g(2);
        self.licensed_irc = lic & 1 != 0;
        self.events.push(Event::License {
            irc: lic & 1 != 0,
            playback: lic & 2 != 0,
            murc: lic & 4 != 0,
        });
        let flags = g(3);
        if flags & 2 != 0 {
            self.events.push(Event::VmUrlConnected { floppy: true });
        }
        if flags & 4 != 0 {
            self.events.push(Event::VmUrlConnected { floppy: false });
        }
        self.half_height_capable = flags & 8 != 0;
    }

    fn set_bitspercolor(&mut self, raw: u8) {
        let bpc = 5 - (raw as i32 & 3);
        self.table[PIXGREY].bits = bpc;
        self.table[PIXRGBR].bits = bpc;
        self.table[PIXRGBG].bits = bpc;
        self.table[PIXRGBB].bits = bpc;
        self.table[PIXRGB].bits = 3 * bpc;
        self.cscale = bpc as u32;
        self.bmask = (1u32 << bpc) - 1;
        // Expand a bpc-bit channel to 8 bits once, here, instead of per pixel.
        for v in 0..32u32 {
            self.scale[v as usize] = ((v.min(self.bmask) * 255 + self.bmask / 2) / self.bmask) as u8;
        }
    }

    /// Tall screens (>1616px wide) halve the block height and widen the
    /// block-addressing fields by one bit.
    fn set_halfheight(&mut self, hh: bool) {
        let bits = if hh { 8 } else { 7 };
        self.table[MOVELONGX].bits = bits;
        self.table[MOVEXY0].bits = bits;
        self.table[MOVEXY1].bits = bits;
        self.table[BLKRPTNSTD].bits = bits;
        self.blockheight = if hh { 8 } else { 16 };
        self.pixels = vec![0; self.blockwidth * self.blockheight];
    }

    fn store_pixel(&mut self, color: u16, count: usize) {
        let end = (self.pixel_count + count).min(self.pixels.len());
        if self.pixel_count < end {
            self.pixels[self.pixel_count..end].fill(color);
        }
        self.pixel_count += count;
        self.last_color = color;
    }

    /// Emit the current block `count` times, walking left-to-right and wrapping.
    fn next_block(&mut self, count: usize, fb: &mut ast2100::Decoder) {
        self.next_state = START;
        self.pixel_count = 0;
        let (w, h) = (self.blockwidth as i32, self.blockheight as i32);
        for _ in 0..count {
            self.blit(self.lastx * w, self.lasty * h, fb);
            self.lastx += 1;
            if self.lastx > self.sizex {
                self.lastx = self.sizex - self.lastx;
                self.lasty += 1;
                if self.lasty > self.sizey {
                    self.lasty = 0;
                }
            }
            self.block_count += 1;
        }
    }

    /// Unpack the block's 16-bit colours into the shared RGB framebuffer.
    fn blit(&self, x0: i32, y0: i32, fb: &mut ast2100::Decoder) {
        let (fw, fh) = (fb.width as i32, fb.height as i32);
        if x0 >= fw || y0 >= fh || x0 + self.blockwidth as i32 <= 0 || y0 + self.blockheight as i32 <= 0 {
            return;
        }
        let (xs, ys) = (x0.max(0), y0.max(0));
        let (xe, ye) = ((x0 + self.blockwidth as i32).min(fw), (y0 + self.blockheight as i32).min(fh));
        fb.mark(xs as usize, ys as usize, (xe - xs) as usize, (ye - ys) as usize);
        let (cs, bmask) = (self.cscale, self.bmask);
        for row in 0..self.blockheight as i32 {
            let y = y0 + row;
            if y < 0 || y >= fh {
                continue;
            }
            let src = row as usize * self.blockwidth;
            let dst = y as usize * fb.width;
            for col in 0..self.blockwidth as i32 {
                let x = x0 + col;
                if x < 0 || x >= fw {
                    continue;
                }
                let c = (self.pixels[src + col as usize] >> 1) as u32;
                let b = self.scale[(c & bmask) as usize] as u32;
                let g = self.scale[((c >> cs) & bmask) as usize] as u32;
                let r = self.scale[((c >> (2 * cs)) & bmask) as usize] as u32;
                fb.framebuffer[dst + x as usize] = (r << 16) | (g << 8) | b;
            }
        }
    }
}

fn lead_zeros(b: u8) -> u32 {
    if b == 0 { 8 } else { (b as u32).leading_zeros() - 24 }
}

fn trail_zeros(b: u8) -> u32 {
    if b == 0 { 8 } else { (b as u32).trailing_zeros() }
}

/// The client-texture replay over block sequences: after every run of
/// blocks, a client that paints only the damage must hold the decoder's
/// picture, including blocks clipped at the right and bottom edges and the
/// reference's `lastx = sizex - lastx` wrap, which lands a block off screen.
#[cfg(test)]
mod damage_replay {
    use super::*;
    use crate::damage::tests::Replay;

    #[test]
    fn blocks_mark_what_they_draw() {
        // 100x70 is not a whole number of 16x16 blocks either way.
        let mut fb = ast2100::Decoder::new(100, 70);
        let mut d = Dvc::new();
        let mut rp = Replay::default();
        rp.step(&mut fb, "new");
        (d.sizex, d.sizey) = (6, 4);
        for (step, (x, y, n)) in [(0, 0, 1), (5, 0, 3), (6, 4, 1), (3, 2, 9), (0, 4, 20)].into_iter().enumerate() {
            (d.lastx, d.lasty) = (x, y);
            d.pixels.iter_mut().enumerate().for_each(|(i, p)| *p = ((i * 37 + step * 1000) % 0x7FFF) as u16 * 2);
            d.next_block(n, &mut fb);
            assert!(!rp.step(&mut fb, &format!("step {step}")).unwrap().full);
        }
        // No blocks, no damage.
        assert_eq!(rp.step(&mut fb, "static"), None);
        // A block wholly off screen after the wrap draws and marks nothing.
        (d.lastx, d.lasty) = (-1, 0);
        d.next_block(1, &mut fb);
        assert_eq!(rp.step(&mut fb, "off screen"), None);
    }
}
