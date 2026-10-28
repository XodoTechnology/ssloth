//! Opening and closing consoles, for every family.
//!
//! `open` runs a family's connect on a thread of its own and hands back a
//! `ConnectOk`: the shared framebuffer and telemetry a front end draws from,
//! and the `FamilyLink` that carries input to the console threads, says
//! whether they are still up, and lets go of the console. The pattern is the
//! same for every family: background threads own the sockets, a `Sender`
//! carries pre-encoded input packets to them, and an `AtomicBool` is the
//! liveness flag. No writer ever holds a `Mutex` over a TLS stream, which
//! cannot be split for concurrent reads and writes.
//!
//! `close` keeps every release path the console needs: its media first, then
//! what its family's teardown recorded — iLO's logout, iDRAC's logout and
//! `release_new_sessions`, X9's clock restore. SP-X, Avocent and iDRAC 8 log
//! their web session out from their own console thread once liveness drops.

use crate::events::{Event, Sink};
use crate::families::quanta::kvm::ShareAnswer;
use crate::families::{self, Family};
use crate::jobs::{JobKey, Jobs, Waited};
use crate::takeover::{ami_sharing, Takeover, TakeoverSlot};
use crate::{ast2100, latency, rfb, vmedia};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

/// What closing a console must undo, in the order it was acquired; it runs
/// last first. Each step returns what it could not put back, one line per
/// problem naming the host.
#[derive(Default)]
pub struct Teardown(Vec<(Option<String>, Box<dyn FnOnce() -> Vec<String> + Send>)>);

impl Teardown {
    pub fn push(&mut self, step: impl FnOnce() -> Vec<String> + Send + 'static) {
        self.0.push((None, Box::new(step)));
    }

    /// A step that gives something back to the BMC, named for whoever is
    /// told what a close released.
    pub fn push_as(&mut self, what: &str, step: impl FnOnce() -> Vec<String> + Send + 'static) {
        self.0.push((Some(what.to_string()), Box::new(step)));
    }

    /// What the named steps give back, in the order they run.
    pub fn releases(&self) -> Vec<String> {
        self.0.iter().rev().filter_map(|(what, _)| what.clone()).collect()
    }

    /// Run every step, newest first, and gather their problems.
    pub fn run(self) -> Vec<String> {
        self.0.into_iter().rev().flat_map(|(_, step)| step()).collect()
    }
}

/// A teardown step that waits for a console thread to finish its own
/// release, which it does once liveness drops: without it a close returns
/// before the logout is sent, and a process that exits then never sends it.
fn await_thread(host: &str, what: &str, done: std::sync::mpsc::Receiver<()>)
    -> impl FnOnce() -> Vec<String> + Send + 'static
{
    let (host, what) = (host.to_string(), what.to_string());
    move || match done.recv_timeout(std::time::Duration::from_secs(10)) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) =>
            vec![format!("{host}: the console had not finished its {what} after 10 s")],
        _ => Vec::new(),
    }
}

/// The per-family handle on an open console: the input sender its threads
/// drain, the liveness flag they clear when the console ends, and the
/// teardown that closes it.
pub struct FamilyLink {
    pub tx: Sender<Vec<u8>>,
    pub alive: Arc<AtomicBool>,
    pub teardown: Teardown,
}

impl FamilyLink {
    pub fn new(tx: Sender<Vec<u8>>, alive: Arc<AtomicBool>) -> Self {
        FamilyLink { tx, alive, teardown: Teardown::default() }
    }
}

/// A virtual-media mount on a console, shared between the front end that
/// shows and ejects it and the close that detaches it.
pub type MediaSlot = Arc<Mutex<Option<vmedia::Mount>>>;

/// An open console as a front end holds it: everything its threads share,
/// and what a mount needs. Closing it takes its `Closing`.
pub struct Console {
    pub decoder: Arc<Mutex<ast2100::Decoder>>,
    pub tx: Sender<Vec<u8>>,
    pub alive: Arc<AtomicBool>,
    pub host: String,
    pub user: String,
    pub pass: String,
    pub title: String,
    pub media: MediaSlot,
    /// Which family's console/input/vmedia path this session uses.
    pub family: Family,
    /// Per-session console token: the Quanta kvmToken, or the iLO session key.
    pub kvm_token: String,
    /// Live line from the iLO command channel (POST code, power, health).
    pub notice: Arc<Mutex<String>>,
    /// Another user's request for this console, waiting on an answer.
    pub takeover: TakeoverSlot,
    /// Why the console stopped, when its thread could tell; empty otherwise.
    pub ended: Arc<Mutex<String>>,
    /// iDRAC 9: web session, console tickets and the teardown baseline.
    pub idrac: Option<IdracSession>,
    /// Avocent: the web session the console is running on. Shared rather than
    /// re-created for a mount, because the BMC mints media credentials against
    /// a live web session and its session pool is small enough to notice a
    /// second one. The console thread logs it out when the console ends.
    pub avocent: Option<Arc<crate::families::avocent::Session>>,
    /// SP-X: the web session the console runs on. A mount borrows its cookie
    /// for the media tunnel, alongside the console's KVM token.
    pub spx: Option<Arc<crate::families::spx::Session>>,
    /// Network round trip to the BMC, sampled on a throwaway TCP connect.
    pub net: Arc<latency::Tracker>,
    /// Console round trip, where the protocol can be asked a question that gets
    /// an immediate answer. Stays empty for the push-video families.
    pub rtt: Arc<latency::Tracker>,
    /// Interval between decoded frames — smoothness rather than latency.
    pub frame: Arc<latency::Tracker>,
}

impl Console {
    /// The app's own word on this session, kept apart from the BMC's
    /// `notice` so neither is taken for the other. Said while the console is
    /// up, not only when it closes: what is left behind then blocks the next
    /// mount until it times out.
    pub fn note(&self) -> Option<String> {
        let cause = self.idrac.as_ref()?.baseline.as_ref().err()?;
        Some(format!("could not list iDRAC sessions ({cause}); this console's will be left \
to time out when it closes"))
    }
}

/// What closing a console needs, apart from the `Console` a front end draws.
pub struct Closing {
    pub host: String,
    pub alive: Arc<AtomicBool>,
    pub media: MediaSlot,
    pub teardown: Teardown,
}

/// Split a finished connect into the console a front end holds and what
/// closes it. `user` and `pass` are the credentials a mount uses.
pub fn adopt(ok: ConnectOk, host: &str, user: String, pass: String) -> (Console, Closing) {
    let media: MediaSlot = Default::default();
    let closing = Closing {
        host: host.to_string(),
        alive: ok.link.alive.clone(),
        media: media.clone(),
        teardown: ok.link.teardown,
    };
    let console = Console {
        decoder: ok.decoder, tx: ok.link.tx, alive: ok.link.alive,
        host: host.to_string(), user, pass, title: ok.title, media,
        family: ok.family, kvm_token: ok.kvm_token, notice: ok.notice,
        takeover: ok.takeover, ended: ok.ended, idrac: ok.idrac,
        avocent: ok.avocent, spx: ok.spx,
        net: ok.net, rtt: ok.rtt, frame: ok.frame,
    };
    (console, closing)
}

/// Tear a console down. Returns what could not be put back, one line per
/// problem naming the host, so it reaches a status bar or, at exit, stderr
/// instead of being lost. Blocks for seconds: run it off a UI thread.
pub fn close(c: Closing) -> Vec<String> {
    let mut problems = Vec::new();
    c.alive.store(false, Ordering::SeqCst);
    // The mount first: it may share the console's hold on the clock,
    // and the last to let go is the one that restores it.
    let mount = c.media.lock().unwrap().take();
    if let Some(m) = mount { problems.extend(m.unmount()); }
    // Then the family's own: web sessions back to the BMC (both iLO and
    // iDRAC keep small pools), iDRAC's console and media sessions, and the
    // real BMC clock (and its NTP) if we rolled it back for X9's expired
    // certificate and nothing else on that BMC still holds it.
    problems.extend(c.teardown.run());
    problems
}


/// Everything an iDRAC console session needs to run and, just as importantly,
/// to tear itself down. iDRAC accounts the web login, the console channel and
/// the media channel as three separate sessions, and only the first is released
/// by logging out — so we remember what existed beforehand and delete the rest.
pub struct IdracSession {
    pub web: crate::families::idrac::Session,
    pub launch: crate::families::idrac::Launch,
    /// The rotated media ticket, shared with the console thread.
    pub key2: Arc<Mutex<String>>,
    /// Session ids present before we connected, or why they could not be
    /// listed — and then nothing is released, since ours cannot be told apart.
    pub baseline: Result<Vec<String>, String>,
}


/// A console that came up: what its threads share with a front end, and the
/// link that closes it.
pub struct ConnectOk {
    pub decoder: Arc<Mutex<ast2100::Decoder>>,
    pub link: FamilyLink,
    pub title: String,
    /// Which family's console/input/vmedia path this session uses.
    pub family: Family,
    /// Per-session console token: the Quanta kvmToken (which also authenticates
    /// IUSB virtual media), or the iLO web session key.
    pub kvm_token: String,
    /// Live line from the iLO command channel; stays empty for other families.
    pub notice: Arc<Mutex<String>>,
    pub takeover: TakeoverSlot,
    pub ended: Arc<Mutex<String>>,
    /// iDRAC 9: web session, console tickets and the teardown baseline.
    pub idrac: Option<IdracSession>,
    /// Avocent: the web session the console runs on, shared with the mount path.
    pub avocent: Option<Arc<crate::families::avocent::Session>>,
    pub spx: Option<Arc<crate::families::spx::Session>>,
    /// Latency trackers, shared with whichever thread takes the samples.
    pub net: Arc<latency::Tracker>,
    pub rtt: Arc<latency::Tracker>,
    pub frame: Arc<latency::Tracker>,
}

/// The three trackers a session carries, created together at connect.
pub fn trackers() -> (Arc<latency::Tracker>, Arc<latency::Tracker>, Arc<latency::Tracker>) {
    (latency::Tracker::new(), latency::Tracker::new(), latency::Tracker::new())
}

/// Connect a Quanta/AMI MegaRAC BMC's JViewer (IVTP) console: self-fetch a launch
/// token, run the video handshake on :7578, and feed decoded AST2300 frames into a
/// shared decoder that the GUI renders, and drives keyboard/mouse over IVTP HID.
fn quanta_connect(host: &str, user: &str, pass: &str, progress: &Arc<Mutex<String>>,
                  vendor: families::Vendor)
    -> Result<ConnectOk, String>
{
    let say = |m: &str| { *progress.lock().unwrap() = m.to_string(); };
    say("Quanta: fetching KVM launch token…");
    let launch = crate::families::quanta::fetch_kvm_launch(host, user, pass)
        .map_err(|e| format!("launch: {e}"))?;
    say("Quanta: IVTP video handshake…");
    let conn = crate::families::quanta::kvm::connect(host, &launch.web_cookie, launch.kvm_token.as_bytes())
        .map_err(|e| format!("handshake: {e}"))?;
    let mut sock = conn.sock;
    // Frames stream continuously; a longer read timeout tolerates a static screen.
    sock.set_read_timeout(Some(std::time::Duration::from_secs(20))).ok();
    let decoder = Arc::new(Mutex::new(ast2100::Decoder::new(1024, 768)));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let alive = Arc::new(AtomicBool::new(true));
    let (net, rtt, frame) = trackers();
    // Writer thread: drain the input channel (pre-encoded IVTP HID packets from the
    // GUI) to the BMC over a cloned socket.
    if let Ok(mut wsock) = sock.try_clone() {
        let wlive = alive.clone();
        std::thread::spawn(move || {
            while wlive.load(Ordering::SeqCst) {
                match rx.recv() {
                    Ok(b) => { if wsock.write_all(&b).is_err() { return; } }
                    Err(_) => return,
                }
            }
        });
    }
    let (dec, live) = (decoder.clone(), alive.clone());
    let frames = latency::Intervals::new(frame.clone());
    let takeover: TakeoverSlot = Default::default();
    let notice = Arc::new(Mutex::new(String::new()));
    let (slot, note, reply) = (takeover.clone(), notice.clone(), tx.clone());
    let ended: Arc<Mutex<String>> = Default::default();
    let why = ended.clone();
    std::thread::spawn(move || {
        use crate::families::quanta::kvm::{read_frame, VIDEO_FRAGMENT, STOP_SESSION};
        let is_hdr = |p: &[u8]| p.len() >= 8 && p[2] == 1 && p[3] == 0 && p[4] == 0x56 && p[5] == 0;
        let mut cur: Vec<u8> = Vec::new();
        while live.load(Ordering::SeqCst) {
            match read_frame(&mut sock) {
                Ok(f) if f.ty == VIDEO_FRAGMENT => {
                    let p = &f.payload;
                    if p.len() < 2 { continue; }
                    // A header-fragment starts a new frame: decode the completed one.
                    if is_hdr(p) && cur.len() > 86 {
                        let (sx, sy) = (u16::from_le_bytes([cur[4], cur[5]]) as usize,
                                        u16::from_le_bytes([cur[6], cur[7]]) as usize);
                        let mode420 = cur[55] != 0;
                        if sx > 0 && sy > 0 && sx <= 4096 && sy <= 4096 {
                            dec.lock().unwrap().decode_ami_frame(sx, sy, mode420, cur[44] as usize, cur[47] as usize, cur[45] == 1, &cur[86..]);
                            frames.tick();
                        }
                        cur.clear();
                    }
                    cur.extend_from_slice(&p[2..]);
                }
                Ok(f) if f.ty == STOP_SESSION => {
                    *why.lock().unwrap() = "The BMC stopped the console session. Another user may have taken it over, or the session timed out.".into();
                    live.store(false, Ordering::SeqCst);
                    return;
                }
                Ok(f) => {
                    if let Some(ev) = crate::families::quanta::kvm::sharing_event(f.ty, f.status, &f.payload) {
                        ami_sharing(ev, &slot, &note, &reply);
                    }
                }
                Err(_) => { live.store(false, Ordering::SeqCst); return; }
            }
        }
    });
    Ok(ConnectOk {
        decoder, link: FamilyLink::new(tx, alive),
        title: format!("{} · {host}", families::controller_label(Family::Quanta, vendor)),
        family: Family::Quanta,
        kvm_token: launch.kvm_token.clone(),
        notice,
        takeover,
        ended,
        idrac: None,
        avocent: None,
        spx: None,
        net, rtt, frame,
    })
}

/// Connect an HP iLO 4 Integrated Remote Console: log in for a web session key,
/// open the KVM and command WebSocket channels, and decode the DVC video stream
/// into the shared framebuffer the GUI renders.
///
/// One thread owns each channel. `native_tls` streams cannot be split for
/// concurrent read/write, so the KVM thread interleaves draining the input
/// channel with short non-blocking reads instead of using a writer thread.
/// Connect an AMI MegaRAC SP-X console (ASRock Rack and friends): log in to the
/// REST API, mint a KVM token, then run IVTP over `wss://<host>/kvm`.
///
/// The video and input are the Quanta family's — same AST codec, same IUSB HID
/// packets — but the transport is a WebSocket, which cannot be split for
/// concurrent read and write, so one thread interleaves draining the input
/// channel with polling for video, exactly as the iLO and iDRAC paths do.
fn spx_connect(host: &str, user: &str, pass: &str, progress: &Arc<Mutex<String>>,
               vendor: families::Vendor, td: &mut Teardown)
    -> Result<ConnectOk, String>
{
    use crate::families::spx::{self, kvm as spx_kvm};
    let say = |m: &str| { *progress.lock().unwrap() = m.to_string(); };

    say("SP-X: logging in…");
    let sess = spx::login(host, user, pass).map_err(|e| e.to_string())?;
    say("SP-X: fetching the console token…");
    let launch = match spx::kvm_launch(host, &sess) {
        Ok(l) => l,
        Err(e) => { spx::logout(host, &sess); return Err(e.to_string()); }
    };
    say("SP-X: IVTP handshake…");
    let mut con = match spx_kvm::connect(host, &sess.cookie, &launch, &|m| say(&format!("SP-X: {m}"))) {
        Ok(c) => c,
        Err(e) => { spx::logout(host, &sess); return Err(format!("console: {e}")); }
    };
    // Short poll timeout: this is also how often queued keystrokes get sent.
    con.sock.set_poll_timeout(std::time::Duration::from_millis(20)).ok();

    let decoder = Arc::new(Mutex::new(ast2100::Decoder::new(1024, 768)));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let alive = Arc::new(AtomicBool::new(true));
    let (net, rtt, frame) = trackers();
    latency::spawn_net_probe(host.to_string(), 443, alive.clone(), net.clone(),
                             std::time::Duration::from_secs(5));

    let (dec, live) = (decoder.clone(), alive.clone());
    let frames = latency::Intervals::new(frame.clone());
    let sess = Arc::new(sess);
    let (logout_host, logout_sess) = (host.to_string(), sess.clone());
    let takeover: TakeoverSlot = Default::default();
    let notice = Arc::new(Mutex::new(String::new()));
    let (slot, note, reply) = (takeover.clone(), notice.clone(), tx.clone());
    let ended: Arc<Mutex<String>> = Default::default();
    let why = ended.clone();
    let (gone_tx, gone_rx) = std::sync::mpsc::channel::<()>();
    td.push_as("SP-X console and web session", await_thread(host, "logout", gone_rx));
    std::thread::spawn(move || {
        let _gone = gone_tx;
        let mut asm = spx_kvm::VideoAssembler::default();
        let _ = con.request_full_screen();
        // Keys typed while the BMC attaches its keyboard are held, not lost
        // (see `Console::media_info`), and the notice says why nothing shows yet.
        const ATTACHING: &str = "attaching the keyboard to the host — keys typed now follow in a moment";
        let (mut attaching, mut before) = (false, String::new());
        while live.load(Ordering::SeqCst) {
            while let Ok(b) = rx.try_recv() {
                if con.send_input(b).is_err() {
                    live.store(false, Ordering::SeqCst);
                    break;
                }
            }
            if con.flush_input().is_err() {
                live.store(false, Ordering::SeqCst);
                break;
            }
            if con.hid_attaching() != attaching {
                attaching = !attaching;
                let mut n = note.lock().unwrap();
                if attaching {
                    before = std::mem::replace(&mut *n, ATTACHING.into());
                } else if *n == ATTACHING {
                    *n = std::mem::take(&mut before);
                }
            }
            let f = match con.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(_) => { live.store(false, Ordering::SeqCst); break; }
            };
            match f.ty {
                spx_kvm::CMD_VIDEO_PACKETS => {
                    dec.lock().unwrap().bytes_in += f.payload.len() as u64;
                    if let Some((h, data)) = asm.push(&f.payload) {
                        dec.lock().unwrap().decode_ami_frame(
                            h.width, h.height, h.mode420, h.jpeg_table, h.advance_table, h.yuv_mapping, &data);
                        frames.tick();
                    }
                }
                // Unanswered keep-alives are treated as a dead client.
                spx_kvm::CMD_KEEP_ALIVE_PKT => { let _ = con.keep_alive(); }
                spx_kvm::CMD_STOP_SESSION_IMMEDIATE => {
                    *why.lock().unwrap() = "The BMC stopped the console session. Another user may have taken it over, or the session timed out.".into();
                    live.store(false, Ordering::SeqCst);
                    break;
                }
                _ => {
                    if let Some(ev) = crate::families::quanta::kvm::sharing_event(f.ty, f.status, &f.payload) {
                        ami_sharing(ev, &slot, &note, &reply);
                    }
                }
            }
        }
        // Always close both: the BMC counts the console and the web session
        // separately and holds each until its own timeout otherwise.
        con.close();
        crate::families::spx::logout(&logout_host, &logout_sess);
    });

    Ok(ConnectOk {
        decoder, link: FamilyLink::new(tx, alive),
        title: format!("{} · {host}", families::controller_label(Family::Spx, vendor)),
        family: Family::Spx,
        kvm_token: launch.token.clone(),
        notice,
        takeover,
        ended,
        idrac: None,
        avocent: None,
        spx: Some(sess),
        net, rtt, frame,
    })
}

/// Connect a Gigabyte/Avocent MergePoint console: log in to the web UI, mint
/// one-shot console credentials, then run APCP/AVSP on :2068.
///
/// Unlike the other non-ATEN families this one gets two sockets — control and
/// video — so each thread can block on its own reads instead of interleaving
/// sends with short polls. The web session is held open for the whole session
/// and logged out at the end, because the BMC ties the console credentials to
/// it and refuses the console the moment it goes away.
fn avocent_connect(host: &str, user: &str, pass: &str, progress: &Arc<Mutex<String>>,
                   family: Family, vendor: families::Vendor, td: &mut Teardown)
    -> Result<ConnectOk, String>
{
    use crate::families::avocent::{self, kvm as avocent_kvm, Launch, Session};
    use crate::families::idrac8;
    let say = |m: &str| { *progress.lock().unwrap() = m.to_string(); };
    // iDRAC 8 is the same console behind Dell's web login.
    type Login = fn(&str, &str, &str) -> std::io::Result<Session>;
    type Mint = fn(&str, &Session) -> std::io::Result<Launch>;
    let (name, login, kvm_launch, logout): (&str, Login, Mint, fn(&str, &Session)) =
        if family == Family::Idrac8 {
            ("iDRAC 8", idrac8::login, idrac8::kvm_launch, idrac8::logout)
        } else {
            ("Avocent", avocent::login, avocent::kvm_launch, avocent::logout)
        };

    say(&format!("{name}: logging in…"));
    let sess = login(host, user, pass).map_err(|e| e.to_string())?;
    say(&format!("{name}: minting console credentials…"));
    let launch = match kvm_launch(host, &sess) {
        Ok(l) => l,
        Err(e) => { logout(host, &sess); return Err(e.to_string()); }
    };
    say(&format!("{name}: APCP/AVSP handshake…"));
    let mut con = match avocent_kvm::connect(host, &launch) {
        Ok(c) => c,
        Err(e) => { logout(host, &sess); return Err(format!("console: {e}")); }
    };
    if let Err(e) = con.start_video(1024, 768) {
        con.close();
        logout(host, &sess);
        return Err(format!("console: {e}"));
    }

    let decoder = Arc::new(Mutex::new(ast2100::Decoder::new(1024, 768)));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let alive = Arc::new(AtomicBool::new(true));
    let (net, rtt, frame) = trackers();
    latency::spawn_net_probe(host.to_string(), 443, alive.clone(), net.clone(),
                             std::time::Duration::from_secs(5));

    let (mut kvm, mut video) = con.split();
    kvm.set_poll_timeout(std::time::Duration::from_millis(20));
    video.set_poll_timeout(std::time::Duration::from_millis(200));

    // Control channel: pre-encoded HID packets out, BMC state in, and the
    // keep-alive the BMC expects every ten seconds. It also owns the teardown,
    // because the web session has to outlive the console.
    // The mount path needs this session too, so it is shared rather than moved;
    // the control thread still owns the logout, which is the one teardown that
    // has to happen exactly once.
    let sess = Arc::new(sess);
    let (clive, logout_host, logout_sess) = (alive.clone(), host.to_string(), sess.clone());
    let (gone_tx, gone_rx) = std::sync::mpsc::channel::<()>();
    td.push_as(&format!("{name} console and web session"), await_thread(host, "logout", gone_rx));
    std::thread::spawn(move || {
        let _gone = gone_tx;
        let mut next_ka = std::time::Instant::now() + avocent_kvm::KEEPALIVE_EVERY;
        while clive.load(Ordering::SeqCst) {
            while let Ok(b) = rx.try_recv() {
                if kvm.send(&b).is_err() {
                    clive.store(false, Ordering::SeqCst);
                    break;
                }
            }
            if std::time::Instant::now() >= next_ka {
                if kvm.send(&avocent_kvm::keep_alive()).is_err() {
                    clive.store(false, Ordering::SeqCst);
                    break;
                }
                next_ka = std::time::Instant::now() + avocent_kvm::KEEPALIVE_EVERY;
            }
            // Drain whatever the BMC pushes (resolution changes, keyboard LEDs,
            // the shared-user list). A channel that is never read eventually
            // stalls the BMC's writer and takes the video down with it.
            match kvm.poll() {
                Ok(_) => {}
                Err(_) => { clive.store(false, Ordering::SeqCst); break; }
            }
        }
        let _ = kvm.send(&avocent_kvm::video_enable(false));
        kvm.shutdown();
        logout(&logout_host, &logout_sess);
    });

    // Video channel: nothing to send after the handshake, so it just decodes.
    let (dec, vlive) = (decoder.clone(), alive.clone());
    let frames = latency::Intervals::new(frame.clone());
    std::thread::spawn(move || {
        let mut codec = avocent_kvm::Video::default();
        while vlive.load(Ordering::SeqCst) {
            let f = match video.poll() {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(_) => break,
            };
            // Flow control: the BMC stops after 96 unacknowledged video packets.
            if avocent_kvm::needs_ack(f.id) && video.send(&avocent_kvm::video_ack(1)).is_err() {
                break;
            }
            if f.id == avocent_kvm::msg::VIDEO_STOPPED {
                break;
            }
            if codec.feed(&f, &mut dec.lock().unwrap()) {
                frames.tick();
            }
        }
        vlive.store(false, Ordering::SeqCst);
        video.shutdown();
    });

    Ok(ConnectOk {
        decoder, link: FamilyLink::new(tx, alive),
        title: match (family, vendor) {
            (Family::Idrac8, _) => format!("Dell · iDRAC 8 · {host}"),
            (_, families::Vendor::Dell) => format!("Dell PowerEdge C · Avocent MergePoint · {host}"),
            _ => format!("Gigabyte · Avocent MergePoint · {host}"),
        },
        family,
        kvm_token: String::new(),
        notice: Arc::new(Mutex::new(String::new())),
        takeover: Default::default(),
        ended: Default::default(),
        idrac: None,
        avocent: Some(sess),
        spx: None,
        net, rtt, frame,
    })
}

fn ilo4_connect(host: &str, user: &str, pass: &str, progress: &Arc<Mutex<String>>, seize: bool,
                td: &mut Teardown)
    -> Result<ConnectOk, String>
{
    use crate::families::ilo4::{self, kvm as ilo4_kvm};
    let say = |m: &str| { *progress.lock().unwrap() = m.to_string(); };

    say("iLO: logging in…");
    let sess = ilo4::login(host, user, pass).map_err(|e| e.to_string())?;
    // Logged out however this ends, a failed connect included: iLO keeps
    // only a handful of web sessions, and a stranded one holds its slot for
    // the 30-minute idle timeout.
    let (out_host, out_key) = (host.to_string(), sess.key.clone());
    td.push_as("iLO web session", move || { ilo4::logout(&out_host, &out_key); Vec::new() });
    if !sess.remote_console {
        return Err("this account lacks the Remote Console privilege".into());
    }
    let info = ilo4::detect(host);

    // Not seizing unless asked: a console in use is reported, and the connecting
    // screen offers "Take over" — iLO's own client asks before it acquires too.
    say("iLO: opening console channel…");
    let mut kvm = ilo4_kvm::open(host, &sess.key, ilo4_kvm::KVM_CHANNEL, seize)
        .map_err(|e| format!("console channel: {e}"))?;
    say("iLO: opening command channel…");
    let mut cmd = match ilo4_kvm::open(host, &sess.key, ilo4_kvm::CMD_CHANNEL, seize) {
        Ok(c) => c,
        Err(e) => {
            kvm.close();
            return Err(format!("command channel: {e}"));
        }
    };

    // Short poll timeouts keep input latency down on an otherwise idle screen.
    kvm.set_poll_timeout(std::time::Duration::from_millis(20)).ok();
    cmd.set_poll_timeout(std::time::Duration::from_millis(200)).ok();

    let decoder = Arc::new(Mutex::new(ast2100::Decoder::new(1024, 768)));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let alive = Arc::new(AtomicBool::new(true));
    let notice = Arc::new(Mutex::new(String::new()));
    let (net, rtt, frame) = trackers();

    // Video + input.
    // Why the console ended, when the iLO says: the video channel's own
    // session-end command, a reset, or a take-over this user granted.
    let ended: Arc<Mutex<String>> = Default::default();
    let why = ended.clone();
    let (dec, live) = (decoder.clone(), alive.clone());
    let frames = latency::Intervals::new(frame.clone());
    std::thread::spawn(move || {
        use crate::ilo_dvc::Event;
        let mut dvc = crate::ilo_dvc::Dvc::new();
        // Start from a known keyboard state and ask for a full frame.
        let _ = kvm.send_binary(&ilo4_kvm::all_keys_up());
        let _ = kvm.send_binary(&ilo4_kvm::refresh());
        while live.load(Ordering::SeqCst) {
            while let Ok(b) = rx.try_recv() {
                if kvm.send_binary(&b).is_err() {
                    live.store(false, Ordering::SeqCst);
                    return;
                }
            }
            let msg = match kvm.poll() {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(_) => { live.store(false, Ordering::SeqCst); break; }
            };
            let before = dec.lock().unwrap().frames;
            let events = dvc.process(&msg, &mut dec.lock().unwrap());
            if dec.lock().unwrap().frames > before {
                frames.tick();
            }
            for e in events {
                let out = match e {
                    // The BMC withholds further video until we acknowledge.
                    Event::SendAck => Some(ilo4_kvm::ack()),
                    Event::Refresh => Some(ilo4_kvm::refresh()),
                    Event::Exit => {
                        let mut w = why.lock().unwrap();
                        if w.is_empty() { *w = "The iLO ended the console session.".into(); }
                        drop(w);
                        live.store(false, Ordering::SeqCst);
                        break;
                    }
                    _ => None,
                };
                if let Some(b) = out {
                    if kvm.send_binary(&b).is_err() {
                        live.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
        }
        // Always close: the BMC holds the console session open otherwise.
        kvm.close();
    });

    // iLO expires idle web sessions, and virtual media authenticates with the
    // same key, so keep it warm for as long as the console is up.
    let (live3, key) = (alive.clone(), sess.key.clone());
    let tick_host = host.to_string();
    std::thread::spawn(move || {
        while live3.load(Ordering::SeqCst) {
            for _ in 0..150 {
                if !live3.load(Ordering::SeqCst) { return; }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            if !ilo4::tickle(&tick_host, &key) { return; }
        }
    });

    // Notifications: power/health/POST code, and requests from other users.
    let (live2, note, why2) = (alive.clone(), notice.clone(), ended.clone());
    let takeover: TakeoverSlot = Default::default();
    let slot = takeover.clone();
    // Answers to takeover requests go back on this channel: the command socket
    // belongs to this thread, and a TLS stream cannot be shared across threads.
    let (answer_tx, answer_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use crate::families::ilo4::kvm::Event;
        while live2.load(Ordering::SeqCst) {
            while let Ok(b) = answer_rx.try_recv() {
                let _ = cmd.send_binary(&b);
            }
            let msg = match cmd.poll() {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(_) => break, // the video channel decides when we're done
            };
            let Some(n) = ilo4_kvm::parse_notification(&msg) else { continue };
            let set = |m: String| { *note.lock().unwrap() = m; };
            match ilo4_kvm::interpret(&n) {
                Event::Power(on) => set(format!("power {}", if on { "on" } else { "off" })),
                Event::Health(h) => set(format!("health {h}")),
                Event::PostCode(c) => set(format!("POST {c}")),
                Event::PostComplete => set("POST complete".into()),
                Event::MediaResult { ok, reason, connected, .. } => set(if ok {
                    format!("virtual media {}", if connected { "connected" } else { "disconnected" })
                } else {
                    format!("virtual media: {reason}")
                }),
                // Take-over: ask, as the vendor console does — and, like it,
                // hand the console over if nobody answers within 10 seconds, so an
                // unattended session does not lock everyone else out.
                Event::SeizeRequest { user, addr } => {
                    let (tx, why3, taker) = (answer_tx.clone(), why2.clone(), user.clone());
                    slot.post(Takeover {
                        question: format!("{user} wants to take over this console. Yours will close."),
                        user, addr,
                        answers: vec![(ShareAnswer::Full, "Give it to them"), (ShareAnswer::Deny, "Keep it")],
                        lasts: std::time::Duration::from_secs(10),
                        on_timeout: Some(ShareAnswer::Full),
                        respond: Box::new(move |a| {
                            if a == ShareAnswer::Full {
                                *why3.lock().unwrap() = format!("You gave the console to {taker}.");
                            }
                            let _ = tx.send(if a == ShareAnswer::Full { ilo4_kvm::grant() } else { ilo4_kvm::deny() });
                        }),
                    });
                }
                // Sharing would need this client to relay the video to them, which
                // it cannot; the vendor's HTML5 console declines these too.
                Event::ShareRequest { user, addr } => {
                    let _ = cmd.send_binary(&ilo4_kvm::deny());
                    set(format!("declined {user} ({addr}): this client cannot share the console"));
                }
                Event::Unauthorized(p) => set(format!("not authorised for {p}")),
                Event::LicenseViolation => set("console is not licensed".into()),
                Event::FirmwareUpdate | Event::IloReset => {
                    set("iLO is restarting".into());
                    *why2.lock().unwrap() = "The iLO is restarting (a reset or a firmware update), \
which ends every console session.".into();
                    live2.store(false, Ordering::SeqCst);
                    break;
                }
                _ => {}
            }
        }
        cmd.close();
    });

    let title = match &info {
        Some(i) => format!("iLO 4 · {} · fw {}", i.model, i.firmware),
        None => format!("iLO 4 · {host}"),
    };
    Ok(ConnectOk {
        decoder, link: FamilyLink::new(tx, alive), title,
        family: Family::Ilo4,
        kvm_token: sess.key,
        notice,
        takeover,
        ended,
        idrac: None,
        avocent: None,
        spx: None,
        net, rtt, frame,
    })
}

/// Connect a Dell iDRAC 9 virtual console.
///
/// Unlike the other three families this is plain RFB — the BMC runs a VNC server
/// ("OpenVNC") reached over a WebSocket, wrapped in a thin Dell control
/// protocol. One thread owns the socket, interleaving input with reads, because
/// the TLS stream cannot be split.
fn idrac_connect(host: &str, user: &str, pass: &str, progress: &Arc<Mutex<String>>,
                 td: &mut Teardown)
    -> Result<ConnectOk, String>
{
    use crate::families::idrac::{self, kvm as idrac_kvm};
    let say = |m: &str| { *progress.lock().unwrap() = m.to_string(); };

    // Snapshot before anything: the console and media channels each create a
    // session that survives closing their socket.
    let baseline = idrac::session_ids(host, user, pass);
    say("iDRAC: logging in…");
    let sess = idrac::login(host, user, pass).map_err(|e| e.to_string())?;
    // From here a failed connect releases what it opened, as a close does:
    // the web session logged out, then every session new since the
    // baseline. One it could not release is a problem, not the error,
    // which a cancel throws away.
    {
        let (h, u, p, b) = (host.to_string(), user.to_string(), pass.to_string(), baseline.clone());
        td.push_as("iDRAC console and media sessions", move || match idrac::release_new_sessions(&h, &u, &p, &b) {
            Ok(_) => Vec::new(),
            Err(e) => vec![format!("{h}: {e}")],
        });
        let (h, web) = (host.to_string(), sess.clone());
        td.push_as("iDRAC web session", move || { idrac::logout(&h, &web); Vec::new() });
    }
    let info = idrac::detect(host);

    say("iDRAC: requesting a console ticket…");
    let launch = idrac::launch_console(host, &sess).map_err(|e| e.to_string())?;
    say("iDRAC: console handshake…");
    // Shared, as the vendor console does: an exclusive request is refused
    // outright by BMCs whose Virtual Console access policy denies sharing.
    let mut con = idrac_kvm::connect(host, &sess.cookie, &launch, true).map_err(|e| e.to_string())?;
    // The console thread closes its own socket once `alive` clears; give it
    // a moment at close, before the logout and the release above.
    td.push(|| { std::thread::sleep(std::time::Duration::from_millis(300)); Vec::new() });
    // Virtual media authenticates with the ticket the BMC rotates once the
    // console is up, so capture it before the console moves to its thread.
    con.wait_media_key(std::time::Duration::from_secs(5));
    let key2 = con.key2.clone();

    let decoder = Arc::new(Mutex::new(ast2100::Decoder::new(con.width, con.height)));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let alive = Arc::new(AtomicBool::new(true));
    let (net, rtt, frame) = trackers();
    let title = match &info {
        Some(i) => format!("iDRAC {} · {} · {}x{}", i.generation, i.firmware, con.width, con.height),
        None => format!("iDRAC 9 · {host} · {}x{}", con.width, con.height),
    };

    let (dec, live) = (decoder.clone(), alive.clone());
    let frames = latency::Intervals::new(frame.clone());
    let rtt_t = rtt.clone();
    let mut con = con;
    std::thread::spawn(move || {
        let mut vdec = crate::vnc::Decoder::new(con.format, true);
        // RFB is request/response, so the console round trip can be measured
        // honestly: a one-pixel non-incremental request must be answered at once.
        let mut pending_ping: Option<std::time::Instant> = None;
        let mut next_ping = std::time::Instant::now();
        while live.load(Ordering::SeqCst) {
            while let Ok(b) = rx.try_recv() {
                if con.stream.send(&b).is_err() {
                    live.store(false, Ordering::SeqCst);
                    break;
                }
            }
            if !live.load(Ordering::SeqCst) {
                break;
            }
            let data = match con.stream.take_rfb() {
                Ok(d) => d,
                Err(_) => { live.store(false, Ordering::SeqCst); break; }
            };
            if data.is_empty() {
                continue;
            }
            let (updates, size) = {
                let mut fb = dec.lock().unwrap();
                match vdec.feed(&data, &mut fb) {
                    Ok(n) => (n, (fb.width as u16, fb.height as u16)),
                    Err(_) => { live.store(false, Ordering::SeqCst); return; }
                }
            };
            // RFB is pull-driven: each update must be asked for.
            if updates > 0 {
                frames.tick();
                if let Some(sent) = pending_ping.take() {
                    rtt_t.record(sent.elapsed());
                }
                vdec.resized = false;
                // Exactly one request is outstanding at a time, so an update can
                // only be answering whichever we sent last. Spend the occasional
                // frame on a ping to measure that round trip honestly.
                let req = if std::time::Instant::now() >= next_ping {
                    pending_ping = Some(std::time::Instant::now());
                    next_ping = std::time::Instant::now() + crate::vnc::PING_INTERVAL;
                    crate::vnc::ping()
                } else {
                    crate::vnc::framebuffer_update_request(true, 0, 0, size.0, size.1)
                };
                if con.stream.send(&req).is_err() {
                    live.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
        // Always close: the BMC holds the console session open otherwise.
        con.stream.close();
    });

    Ok(ConnectOk {
        decoder, link: FamilyLink::new(tx, alive), title,
        family: Family::Idrac9,
        kvm_token: String::new(),
        notice: Arc::new(Mutex::new(String::new())),
        takeover: Default::default(),
        ended: Default::default(),
        idrac: Some(IdracSession { web: sess, launch, key2, baseline }),
        avocent: None,
        spx: None,
        net, rtt, frame,
    })
}

/// The connect thread's `net` context. A route's own stages (the tunnel,
/// its login) land on the connect page with the family's. Opening a console
/// is the user's own action, so a route that background work has stopped
/// trying, such as a jump host that refused a login, is tried once more.
/// Nothing can be asked from here: a route that needs a question answered
/// fails with text that sends the user to `bmc-kvm route test`.
pub fn connect_context(progress: &Arc<Mutex<String>>) -> crate::net::Context {
    crate::net::Context { progress: Some(progress.clone()), deliberate: true, ..Default::default() }
}

/// What one connect is asked to do.
pub struct Attempt {
    pub host: String,
    pub user: String,
    pub pass: String,
    /// The stage the connect page shows, rewritten as the connect goes.
    pub progress: Arc<Mutex<String>>,
    /// Take the console over if another user has it (iLO asks them).
    pub seize: bool,
    /// The brand the inventory knows, which detection cannot see without
    /// logging in.
    pub known: Option<families::Vendor>,
    /// Set by the user's Cancel; checked before each network step that
    /// opens a session.
    pub cancel: Arc<AtomicBool>,
}

/// Open a console on a thread of its own; its result arrives on the
/// receiver, and `ConnectFinished` says when.
pub fn open(attempt: Attempt, jobs: Jobs, sink: Sink) -> Receiver<Result<ConnectOk, String>> {
    open_with(attempt, jobs, sink, connect_family)
}

/// `open` with the family connect given, so a test can stand in for a BMC.
/// The connect pushes onto the teardown whatever it has opened that a close
/// must let go of; if it then fails, that teardown runs here, and on success
/// it becomes the console's `FamilyLink`, so a session is released on every
/// exit path, a failed open included.
pub fn open_with<F>(attempt: Attempt, jobs: Jobs, sink: Sink, connect: F)
    -> Receiver<Result<ConnectOk, String>>
where
    F: FnOnce(&Attempt, &mut Teardown) -> Result<ConnectOk, String> + Send + 'static,
{
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let say = move |p: &Arc<Mutex<String>>, m: &str| { *p.lock().unwrap() = m.to_string(); };
    std::thread::spawn(move || {
        let a = attempt;
        let res = crate::net::with_context(connect_context(&a.progress), || -> Result<ConnectOk, String> {
            // A close of this host still under way would race us: iDRAC's
            // release deletes whatever is new since the old baseline, this
            // console's sessions included, and X9's clock restore could land
            // after our roll-back. So no network work until it is done.
            let closing = JobKey::Close(a.host.clone());
            let waiting = jobs.running(&closing);
            if waiting {
                say(&a.progress, &waiting_for_close(&a.host));
            }
            match jobs.wait_until_done(&closing, CLOSE_WAIT, &a.cancel) {
                Waited::Done => {}
                Waited::Cancelled => return Err("cancelled".into()),
                Waited::TimedOut => return Err(format!("the previous session on {} was still \
closing after {} s; try again once it has finished", a.host, CLOSE_WAIT.as_secs())),
            }
            if waiting {
                say(&a.progress, "Detecting the BMC type…");
            }
            let mut teardown = Teardown::default();
            match connect(&a, &mut teardown) {
                Ok(mut ok) => {
                    ok.link.teardown = teardown;
                    Ok(ok)
                }
                Err(e) => {
                    for p in teardown.run() {
                        sink.emit(Event::Problem(p));
                    }
                    Err(e)
                }
            }
        });
        let _ = done_tx.send(res);
        sink.emit(Event::ConnectFinished { host: a.host.clone() });
    });
    done_rx
}

/// The real connect: detect the family, then open its console.
fn connect_family(a: &Attempt, td: &mut Teardown) -> Result<ConnectOk, String> {
    let (host, user, pass, progress) = (&a.host, &a.user, &a.pass, &a.progress);
    let say = |p: &Arc<Mutex<String>>, m: &str| { *p.lock().unwrap() = m.to_string(); };
    // Each family has its own console transport; pick it before we try
    // to log in, since even the login endpoints differ.
    let (family, vendor) = families::detect_vendor(host);
    // Detection only probes; what follows logs in and opens sessions.
    if a.cancel.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    match family {
        Family::Idrac9 => return idrac_connect(host, user, pass, progress, td),
        Family::Ilo4 => return ilo4_connect(host, user, pass, progress, a.seize, td),
        // Detection cannot see an OEM brand without logging in; the
        // inventory, which the probe filled in, already knows it.
        Family::Quanta => return quanta_connect(host, user, pass, progress,
                                                a.known.unwrap_or(vendor)),
        Family::Spx => return spx_connect(host, user, pass, progress,
                                          a.known.unwrap_or(vendor), td),
        Family::Avocent | Family::Idrac8 =>
            return avocent_connect(host, user, pass, progress, family, vendor, td),
        Family::Aten => {}
    }
    // Detect the generation (X9/X10/X11) and its connection profile.
    let prog = progress.clone();
    let profile = crate::families::aten::discover_with(host, user, pass, &|m| { *prog.lock().unwrap() = m.to_string(); })
        .map_err(|e| format!("discover: {e}"))?;
    // X9 pins a client certificate that expired in 2026, so the BMC
    // clock is held inside its validity for the session, shared with
    // any mount on this BMC. A console that presents none, or one
    // valid at the BMC's own time, leaves it alone.
    let hold = profile.client_identity.as_ref().map(|id| {
        crate::clock::Hold::take(host, user, pass, (id.not_before, id.not_after))
    });
    say(progress, &format!("{}: TLS handshake…", profile.generation.label()));
    let r = crate::families::aten::client_cert::handshake(
        hold.as_ref(), &|m| say(progress, m), || {
            rfb::Rfb::connect_gen(host, profile.kvm_port, &profile.token, profile.kvm_tls,
                                  profile.client_identity.as_ref())
        })
        .map_err(|e| format!("handshake: {e}"));
    // Restored at close, or now if the handshake failed: a connect that
    // fails makes no session, and a problem putting the clock back is kept
    // apart from the error, which a cancel throws away.
    if let Some(h) = hold {
        td.push_as("BMC clock", move || h.release().into_iter().collect());
    }
    let mut r = match r {
        Ok(r) => r,
        Err(e) => {
            say(progress, "restoring the BMC clock…");
            return Err(e);
        }
    };
    say(progress, "negotiating video…");
    let title = format!("{} · {}x{} · {}", profile.generation.label(), r.width, r.height, r.name);
    let decoder = Arc::new(Mutex::new(ast2100::Decoder::new(r.width as usize, r.height as usize)));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let alive = Arc::new(AtomicBool::new(true));
    let (net, rtt, frame) = trackers();
    let dec = decoder.clone();
    let live = alive.clone();
    let frames = latency::Intervals::new(frame.clone());
    std::thread::spawn(move || {
        let _ = r.set_encodings(&[0x57, 0x0000_0101]);
        let _ = r.fb_update_request(false, 0, 0, r.width, r.height);
        while live.load(Ordering::SeqCst) {
            while let Ok(b) = rx.try_recv() {
                if r.write_all(&b).is_err() { live.store(false, Ordering::SeqCst); return; }
            }
            match rfb::pump_message(&mut r, &dec) {
                Ok(true) => frames.tick(),
                Ok(false) => {}
                Err(_) => {
                    live.store(false, Ordering::SeqCst);
                    return;
                }
            }
        }
    });
    Ok(ConnectOk {
        decoder, link: FamilyLink::new(tx, alive), title,
        family: Family::Aten,
        kvm_token: String::new(),
        notice: Arc::new(Mutex::new(String::new())),
        takeover: Default::default(),
        ended: Default::default(),
        idrac: None,
        avocent: None,
        spx: None,
        net, rtt, frame,
    })
}

/// How long a connect waits for the previous session on its host to finish
/// closing. A close (logout, iDRAC's session release, X9's clock restore)
/// takes seconds; one still going after this is better reported than raced.
pub const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The connecting screen's stage while a connect waits on a close.
pub fn waiting_for_close(host: &str) -> String {
    format!("Waiting for the previous session on {host} to close…")
}

/// A connect-thread stage as a step on the connecting screen: the family
/// prefix dropped (the screen already names the host), the trailing ellipsis
/// dropped (the spinner says it is in progress), and the first letter raised.
pub fn step_label(stage: &str) -> String {
    let s = stage.trim();
    let s = match s.split_once(": ") {
        Some((prefix, rest)) if prefix.len() <= 12 && !prefix.contains(' ') => rest,
        _ => s,
    };
    let s = s.trim_end_matches('…').trim_end_matches("...").trim();
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventSink;

    /// Hands each event to the test as it is raised, so the test can wait
    /// for the one that ends a sequence instead of racing the thread.
    struct Channel(Mutex<Sender<Event>>);

    impl EventSink for Channel {
        fn emit(&self, event: Event) {
            let _ = self.0.lock().unwrap().send(event);
        }
    }
    use std::time::Duration;

    #[test]
    fn the_wait_reads_as_one_step() {
        // The connecting screen shows the start's stage as given and the
        // thread's through `step_label`; they must agree, or it lists twice.
        for host in ["10.0.0.1", "fd00::1", "bmc.example"] {
            let stage = waiting_for_close(host);
            assert_eq!(step_label(&stage),
                       format!("Waiting for the previous session on {host} to close"));
            assert_eq!(step_label(&step_label(&stage)), step_label(&stage));
        }
        assert_eq!(step_label("Detecting the BMC type…"), "Detecting the BMC type");
    }

    fn attempt(host: &str) -> Attempt {
        Attempt {
            host: host.into(), user: "admin".into(), pass: "secret".into(),
            progress: Default::default(), seize: false, known: None, cancel: Default::default(),
        }
    }

    /// A console with no BMC behind it: what a family's connect hands back.
    fn fake_ok() -> ConnectOk {
        let (tx, _rx) = std::sync::mpsc::channel();
        let (net, rtt, frame) = trackers();
        ConnectOk {
            decoder: Arc::new(Mutex::new(ast2100::Decoder::new(8, 8))),
            link: FamilyLink::new(tx, Arc::new(AtomicBool::new(true))),
            title: "fake".into(), family: Family::Aten, kvm_token: String::new(),
            notice: Default::default(), takeover: Default::default(), ended: Default::default(),
            idrac: None, avocent: None, spx: None, net, rtt, frame,
        }
    }

    fn counter() -> (Arc<Mutex<Vec<&'static str>>>, impl Fn(&'static str) -> Box<dyn FnOnce() -> Vec<String> + Send>) {
        let log: Arc<Mutex<Vec<&'static str>>> = Default::default();
        let l = log.clone();
        (log, move |what: &'static str| {
            let l = l.clone();
            Box::new(move || { l.lock().unwrap().push(what); Vec::new() }) as Box<dyn FnOnce() -> Vec<String> + Send>
        })
    }

    #[test]
    fn a_failed_open_releases_what_it_opened_and_reports_what_it_could_not() {
        let (log, step) = counter();
        let (events_tx, events) = std::sync::mpsc::channel();
        let sink = Arc::new(Channel(Mutex::new(events_tx)));
        let rx = open_with(attempt("192.0.2.1"), Jobs::default(), sink, move |_, td| {
            td.push(step("logout"));
            td.push(|| vec!["192.0.2.1: could not release a session".to_string()]);
            Err("handshake: refused".into())
        });
        let res = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(res.err().as_deref(), Some("handshake: refused"));
        assert_eq!(*log.lock().unwrap(), ["logout"]);
        // The problem is raised before the result's own event, which the
        // thread raises only after handing the result over: wait for it.
        let mut seen = Vec::new();
        while !matches!(seen.last(), Some(Event::ConnectFinished { .. })) {
            seen.push(events.recv_timeout(Duration::from_secs(5)).expect("the connect's last event"));
        }
        assert_eq!(seen, [
            Event::Problem("192.0.2.1: could not release a session".into()),
            Event::ConnectFinished { host: "192.0.2.1".into() },
        ]);
    }

    #[test]
    fn a_console_closes_through_the_teardown_its_open_recorded_last_first() {
        let (log, step) = counter();
        let rx = open_with(attempt("192.0.2.2"), Jobs::default(), Arc::new(crate::events::Discard), move |_, td| {
            td.push(step("release"));
            td.push(step("logout"));
            Ok(fake_ok())
        });
        let ok = rx.recv_timeout(Duration::from_secs(5)).unwrap().ok().unwrap();
        assert!(log.lock().unwrap().is_empty(), "nothing is released while the console is up");
        let (console, closing) = adopt(ok, "192.0.2.2", "admin".into(), "secret".into());
        assert!(console.alive.load(Ordering::SeqCst));
        assert!(close(closing).is_empty());
        assert!(!console.alive.load(Ordering::SeqCst), "close clears liveness for the threads");
        assert_eq!(*log.lock().unwrap(), ["logout", "release"]);
    }

    #[test]
    fn a_teardown_names_what_it_releases_in_the_order_it_runs() {
        let mut td = Teardown::default();
        td.push_as("web session", Vec::new);
        td.push(Vec::new);
        td.push_as("console sessions", Vec::new);
        assert_eq!(td.releases(), ["console sessions", "web session"]);
    }

    #[test]
    fn a_close_waits_for_a_console_thread_that_releases_its_own() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let done: Arc<AtomicBool> = Default::default();
        let d = done.clone();
        std::thread::spawn(move || {
            let _gone = tx;
            std::thread::sleep(Duration::from_millis(50));
            d.store(true, Ordering::SeqCst);
        });
        assert!(await_thread("192.0.2.4", "logout", rx)().is_empty());
        assert!(done.load(Ordering::SeqCst), "the step returned before the thread let go");
    }

    #[test]
    fn an_open_waits_for_the_close_of_its_host() {
        let jobs = Jobs::default();
        let guard = jobs.begin(JobKey::Close("192.0.2.3".into()), "closing").unwrap();
        let a = attempt("192.0.2.3");
        let progress = a.progress.clone();
        let started: Arc<AtomicBool> = Default::default();
        let s = started.clone();
        let rx = open_with(a, jobs.clone(), Arc::new(crate::events::Discard), move |_, _| {
            s.store(true, Ordering::SeqCst);
            Ok(fake_ok())
        });
        // The waiting stage shows up, and nothing is dialled under it.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while *progress.lock().unwrap() != waiting_for_close("192.0.2.3") {
            assert!(std::time::Instant::now() < deadline, "no waiting stage");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(rx.try_recv().is_err());
        assert!(!started.load(Ordering::SeqCst), "the connect started before the close ended");
        drop(guard);
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap().is_ok());
        assert!(started.load(Ordering::SeqCst));
    }

    #[test]
    fn a_cancel_during_the_wait_opens_nothing() {
        let jobs = Jobs::default();
        let _guard = jobs.begin(JobKey::Close("192.0.2.4".into()), "closing").unwrap();
        let a = attempt("192.0.2.4");
        let cancel = a.cancel.clone();
        let rx = open_with(a, jobs, Arc::new(crate::events::Discard), |_, _| -> Result<ConnectOk, String> {
            panic!("the connect ran after a cancel");
        });
        cancel.store(true, Ordering::SeqCst);
        let res = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(res.err().as_deref(), Some("cancelled"));
    }
}

#[cfg(test)]
mod connect_context_tests {
    use super::*;
    use crate::net::ssh::testing::{echo_tcp, isolate_config, start_with, Options, HOST_FP};
    use crate::routes::{Auth, Kind, Route};

    #[test]
    fn open_kvm_tries_a_refused_login_once_more_and_shows_the_routes_stages() {
        isolate_config();
        let (server, seen) = start_with(Options::default());
        let route = Route {
            name: "gui-c1".into(),
            kind: Kind::Ssh,
            host: server.ip().to_string(),
            port: server.port(),
            user: "ops".into(),
            auth: Auth::Password,
            secret: "wrong horse".into(),
            host_key: HOST_FP.into(),
            ..Default::default()
        };
        let chain = [route];
        let echo = echo_tcp();
        let connect = || crate::net::ssh::connect(&chain, "127.0.0.1", echo, None).unwrap_err().to_string();
        // A startup probe is refused, and the next is answered from memory
        // with a remedy that the connect below makes true.
        connect();
        let e = connect();
        assert!(e.contains("not retried in the background: connect again"), "{e}");
        assert_eq!(seen.passwords(), 1);

        // Open KVM: detection alone makes several connections, and all of
        // them together try the login once.
        let progress = Arc::new(Mutex::new(String::new()));
        let (first, second) = crate::net::with_context(connect_context(&progress), || (connect(), connect()));
        assert!(first.contains("authentication failed"), "{first}");
        assert_eq!(first, second, "the second connection takes the first's answer");
        assert_eq!(seen.passwords(), 2, "tried exactly once more");
        let stage = progress.lock().unwrap().clone();
        assert!(stage.contains("gui-c1"), "the route's stages reach the connect page: {stage:?}");

        // A route that needs a question answered is refused, without a
        // dial, and sent to the command that can ask.
        let mut unsaved = chain[0].clone();
        unsaved.name = "gui-c1b".into();
        unsaved.secret.clear();
        let e = crate::net::with_context(connect_context(&progress), || {
            crate::net::ssh::connect(&[unsaved], "127.0.0.1", echo, None).unwrap_err().to_string()
        });
        assert!(e.contains("bmc-kvm route test gui-c1b") && !e.contains("GUI"), "{e}");
        assert_eq!(seen.dials(), 2);
    }
}
