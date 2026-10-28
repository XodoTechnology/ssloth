//! Console previews: a picture of a host's screen without opening its
//! console, from the BMC's own dashboard capture wherever one exists.
//!
//! Each capture costs the BMC work and, on some families, the console slot
//! itself, so they are limited: one per host at a time, two in all, none for
//! a host whose console is open or opening (Avocent's capture would
//! disconnect it, iLO's would open a second one), and the families whose
//! capture takes the console slot wait to be asked rather than capturing
//! when a host is merely selected.

use crate::families::{self, Family};
use crate::hosts::{self, Host};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A host's screen snapshot, or why there isn't one.
#[derive(Clone)]
pub enum PreviewState {
    Loading,
    /// A preview operation currently owns a real console/capture slot.
    SessionCapture,
    /// Width, height and pixels (0xRRGGBB), ready to upload.
    Image(usize, usize, Arc<Vec<u32>>),
    /// The BMC has no snapshot endpoint we can use, or it refused.
    Unavailable(String),
    /// A capture is possible but costs a console session, so it waits to be
    /// asked for rather than happening on selection.
    OnDemand(String),
}

impl PreviewState {
    fn running(&self) -> bool {
        matches!(self, PreviewState::Loading | PreviewState::SessionCapture)
    }
}

/// What a capture is asked to fetch.
pub struct CaptureRequest {
    pub addr: String,
    pub user: String,
    pub pass: String,
    /// The family already known, else it is detected (seconds of probing).
    pub family: Option<Family>,
    /// The user asked for this capture, rather than selecting the host.
    pub manual: bool,
}

/// Fetch a preview. The second argument marks the capture as holding the
/// console slot, for the families where it does. `capture` but in tests.
pub type CaptureFn = Arc<dyn Fn(&CaptureRequest, &dyn Fn()) -> PreviewState + Send + Sync>;

/// How many captures may run at once, across every host.
pub const MAX_CAPTURES: usize = 2;

/// The previews by address, shared by cloning.
#[derive(Clone)]
pub struct PreviewService {
    states: Arc<Mutex<HashMap<String, PreviewState>>>,
    capture: CaptureFn,
}

impl Default for PreviewService {
    fn default() -> Self {
        Self::with_capture(Arc::new(capture))
    }
}

impl PreviewService {
    /// With a capture of the caller's, for tests.
    pub fn with_capture(capture: CaptureFn) -> Self {
        Self { states: Default::default(), capture }
    }

    /// The preview for `addr`, if one was asked for.
    pub fn get(&self, addr: &str) -> Option<PreviewState> {
        self.states.lock().unwrap().get(addr).cloned()
    }

    /// Whether a capture holds `addr`'s console slot.
    pub fn capturing(&self, addr: &str) -> bool {
        matches!(self.get(addr), Some(PreviewState::SessionCapture))
    }

    /// Drop what is known of `addr`, before asking for a fresh capture.
    pub fn forget(&self, addr: &str) {
        self.states.lock().unwrap().remove(addr);
    }

    /// Fetch the preview for `h`, unless one is already loaded or loading.
    /// `known` is the family the probe or the inventory already found;
    /// `console` whether `h` has a console open or opening, which refuses
    /// the capture. Err says why it was refused.
    pub fn request(&self, h: &Host, known: Option<Family>, manual: bool, console: bool) -> Result<(), String> {
        let addr = h.address.clone();
        {
            let mut states = self.states.lock().unwrap();
            if states.contains_key(&addr) {
                return Ok(());
            }
            if console {
                return Err(format!("{} has its console open; the console is the preview", h.label()));
            }
            if states.values().filter(|s| s.running()).count() >= MAX_CAPTURES {
                return Err("two previews are already being captured; try again when one finishes".into());
            }
            let initial = if manual && matches!(known, Some(Family::Ilo4 | Family::Avocent)) {
                PreviewState::SessionCapture
            } else {
                PreviewState::Loading
            };
            states.insert(addr.clone(), initial);
        }
        let (user, pass) = hosts::credentials_for(h);
        let request = CaptureRequest { addr, user, pass, family: known, manual };
        let (states, capture) = (self.states.clone(), self.capture.clone());
        std::thread::spawn(move || {
            // "Capture screen" is the user's own click; selecting a host is not.
            if request.manual {
                crate::net::begin_action();
            }
            let exclusive = || {
                states.lock().unwrap().insert(request.addr.clone(), PreviewState::SessionCapture);
            };
            let state = capture(&request, &exclusive);
            states.lock().unwrap().insert(request.addr.clone(), state);
        });
        Ok(())
    }
}

/// The capture each family has, if any.
pub fn capture(req: &CaptureRequest, exclusive: &dyn Fn()) -> PreviewState {
    let (addr, u, pw, manual) = (&req.addr, &req.user, &req.pass, req.manual);
    match req.family.unwrap_or_else(|| families::detect(addr)) {
        Family::Idrac9 if !u.is_empty() => {
            match crate::families::idrac::login(addr, u, pw) {
                Ok(sess) => {
                    let img = crate::families::idrac::preview(addr, &sess);
                    crate::families::idrac::logout(addr, &sess);
                    match img {
                        Some(i) => PreviewState::Image(i.width, i.height,
                                                       Arc::new(i.rgb)),
                        None => PreviewState::Unavailable(
                            "the BMC returned no snapshot".into()),
                    }
                }
                Err(e) => PreviewState::Unavailable(e.to_string()),
            }
        }
        Family::Aten if !u.is_empty() => match crate::auth::login(addr, u, pw) {
            Ok(sid) => {
                let img = crate::auth::snapshot(addr, &sid)
                    .and_then(|b| crate::image::decode(&b));
                crate::auth::logout(addr, &sid);
                match img {
                    Some(i) => PreviewState::Image(i.width, i.height, Arc::new(i.rgb)),
                    None => PreviewState::Unavailable(
                        "the BMC returned no snapshot".into()),
                }
            }
            Err(e) => PreviewState::Unavailable(e.to_string()),
        },
        // iLO 4 has no snapshot endpoint at all -- the vendor's own
        // overview thumbnail is the live console stream drawn small --
        // so a picture means opening the console for a moment. That is
        // only done when the user asks for it.
        Family::Ilo4 if !u.is_empty() && manual => {
            exclusive();
            match crate::families::ilo4::login(addr, u, pw) {
                Ok(sess) => {
                    let img = crate::families::ilo4::kvm::snapshot(
                        addr, &sess.key, std::time::Duration::from_secs(10));
                    crate::families::ilo4::logout(addr, &sess.key);
                    match img {
                        Ok(i) => PreviewState::Image(i.width, i.height, Arc::new(i.rgb)),
                        Err(e) => PreviewState::Unavailable(e.to_string()),
                    }
                }
                Err(e) => PreviewState::Unavailable(e.to_string()),
            }
        }
        Family::Ilo4 if !u.is_empty() => PreviewState::OnDemand(
            "iLO has no snapshot endpoint; capture opens a temporary console".into()),
        // MergePoint's dashboard endpoint forces the BMC to capture a
        // fresh frame using the same scarce resource as KVM. On the
        // tested firmware it disconnects an active console, so never
        // run it merely because the host was selected.
        Family::Avocent if !u.is_empty() && manual => {
            exclusive();
            match crate::families::avocent::login(addr, u, pw) {
                Ok(sess) => {
                    let img = crate::families::avocent::preview(addr, &sess);
                    crate::families::avocent::logout(addr, &sess);
                    match img {
                        Ok(i) => PreviewState::Image(i.width, i.height, Arc::new(i.rgb)),
                        Err(e) => PreviewState::Unavailable(e.to_string()),
                    }
                }
                Err(e) => PreviewState::Unavailable(e.to_string()),
            }
        }
        Family::Avocent if !u.is_empty() => PreviewState::OnDemand(
            "Avocent capture uses the console slot and can disconnect KVM".into()),
        // The dashboard's own capture, as on iDRAC 9: no console slot.
        Family::Idrac8 if !u.is_empty() => {
            match crate::families::idrac8::login(addr, u, pw) {
                Ok(sess) => {
                    let img = crate::families::idrac8::preview(addr, &sess);
                    crate::families::idrac8::logout(addr, &sess);
                    match img {
                        Ok(i) => PreviewState::Image(i.width, i.height, Arc::new(i.rgb)),
                        Err(e) => PreviewState::Unavailable(e.to_string()),
                    }
                }
                Err(e) => PreviewState::Unavailable(e.to_string()),
            }
        }
        Family::Idrac9 | Family::Idrac8 | Family::Aten | Family::Ilo4 | Family::Avocent =>
            PreviewState::Unavailable("no credentials".into()),
        f => PreviewState::Unavailable(
            format!("{} has no snapshot endpoint", f.label())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn host(addr: &str) -> Host {
        Host { address: addr.into(), user: "u".into(), password: "p".into(), ..Default::default() }
    }

    /// A capture that waits to be let go, and counts how often it ran.
    fn held() -> (PreviewService, Arc<Mutex<Vec<String>>>, Arc<Mutex<mpsc::Receiver<()>>>, mpsc::Sender<()>) {
        let (go, wait) = mpsc::channel::<()>();
        let wait = Arc::new(Mutex::new(wait));
        let ran: Arc<Mutex<Vec<String>>> = Default::default();
        let (w, r) = (wait.clone(), ran.clone());
        let svc = PreviewService::with_capture(Arc::new(move |req: &CaptureRequest, _exclusive: &dyn Fn()| {
            r.lock().unwrap().push(req.addr.clone());
            let _ = w.lock().unwrap().recv_timeout(Duration::from_secs(5));
            PreviewState::Image(1, 1, Arc::new(vec![0]))
        }));
        (svc, ran, wait, go)
    }

    fn settle(svc: &PreviewService, addr: &str) {
        for _ in 0..200 {
            if !svc.get(addr).is_some_and(|s| s.running()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the capture of {addr} never finished");
    }

    #[test]
    fn one_capture_per_host() {
        let (svc, ran, _wait, go) = held();
        svc.request(&host("192.0.2.1"), Some(Family::Aten), false, false).unwrap();
        svc.request(&host("192.0.2.1"), Some(Family::Aten), true, false).unwrap();
        go.send(()).unwrap();
        settle(&svc, "192.0.2.1");
        assert_eq!(ran.lock().unwrap().len(), 1);
        assert!(matches!(svc.get("192.0.2.1"), Some(PreviewState::Image(..))));
        // A refresh is a forget and a request: it runs again.
        svc.forget("192.0.2.1");
        svc.request(&host("192.0.2.1"), Some(Family::Aten), true, false).unwrap();
        go.send(()).unwrap();
        settle(&svc, "192.0.2.1");
        assert_eq!(ran.lock().unwrap().len(), 2);
    }

    #[test]
    fn two_captures_in_all() {
        let (svc, _ran, _wait, go) = held();
        svc.request(&host("192.0.2.1"), Some(Family::Aten), false, false).unwrap();
        svc.request(&host("192.0.2.2"), Some(Family::Idrac9), false, false).unwrap();
        let e = svc.request(&host("192.0.2.3"), Some(Family::Aten), false, false).unwrap_err();
        assert!(e.contains("two previews"), "{e}");
        assert!(svc.get("192.0.2.3").is_none(), "refused, not queued");
        go.send(()).unwrap();
        go.send(()).unwrap();
        settle(&svc, "192.0.2.1");
        settle(&svc, "192.0.2.2");
        svc.request(&host("192.0.2.3"), Some(Family::Aten), false, false).unwrap();
        go.send(()).unwrap();
        settle(&svc, "192.0.2.3");
    }

    #[test]
    fn no_capture_while_the_console_is_open_or_opening() {
        let (svc, ran, _wait, _go) = held();
        assert!(svc.request(&host("192.0.2.4"), Some(Family::Avocent), true, true).is_err());
        assert!(svc.get("192.0.2.4").is_none());
        assert!(ran.lock().unwrap().is_empty());
    }

    #[test]
    fn a_capture_that_takes_the_console_slot_says_so_from_the_start() {
        let (svc, _ran, _wait, go) = held();
        svc.request(&host("192.0.2.5"), Some(Family::Ilo4), true, false).unwrap();
        assert!(svc.capturing("192.0.2.5"));
        go.send(()).unwrap();
        settle(&svc, "192.0.2.5");
    }

    #[test]
    fn ilo_and_avocent_wait_to_be_asked() {
        // The real capture, offline: neither touches the network unasked.
        let req = |family, manual| CaptureRequest {
            addr: "bmc-x.invalid".into(), user: "u".into(), pass: "p".into(), family: Some(family), manual,
        };
        let never = || panic!("selection must not take the console slot");
        assert!(matches!(capture(&req(Family::Ilo4, false), &never), PreviewState::OnDemand(_)));
        assert!(matches!(capture(&req(Family::Avocent, false), &never), PreviewState::OnDemand(_)));
        assert!(matches!(capture(&req(Family::Spx, false), &never), PreviewState::Unavailable(_)));
        let nobody = CaptureRequest { user: String::new(), ..req(Family::Ilo4, true) };
        assert!(matches!(capture(&nobody, &never), PreviewState::Unavailable(_)));
    }
}
