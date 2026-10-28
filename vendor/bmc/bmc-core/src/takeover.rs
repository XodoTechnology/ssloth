//! Another user's request for a console this client holds, posted by the
//! console thread and answered from a GUI. Every family that asks the holder
//! goes through this one slot per session.
//!
//! Each request has the vendor client's deadline, and what happens at it is
//! the vendor's too: iLO hands the console over after 10 s, so an unattended
//! session cannot lock everyone else out, while the AMI stacks leave the
//! answer to the BMC after 30 s. The deadline runs on a thread of its own,
//! so it is kept whether or not a window is drawing.

use crate::families::quanta::kvm::ShareAnswer;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A request, as the console thread posts it.
pub struct Takeover {
    pub user: String,
    pub addr: String,
    pub question: String,
    /// The answers offered, each with its button label.
    pub answers: Vec<(ShareAnswer, &'static str)>,
    /// How long it may be answered for.
    pub lasts: Duration,
    /// What the vendor client answers when nobody does; None leaves it to the
    /// BMC, which times the request out itself.
    pub on_timeout: Option<ShareAnswer>,
    pub respond: Box<dyn Fn(ShareAnswer) + Send>,
}

/// A pending request, as a dialog shows it.
#[derive(Clone, Debug)]
pub struct Pending {
    pub user: String,
    pub addr: String,
    pub question: String,
    pub answers: Vec<(ShareAnswer, &'static str)>,
    pub on_timeout: Option<ShareAnswer>,
    /// Time left to answer.
    pub left: Duration,
}

/// How a request ended without anyone answering it, for the status line.
#[derive(Clone, Debug, PartialEq)]
pub struct Lapsed {
    pub user: String,
    /// The answer given for the user, if the vendor's rule gives one.
    pub answered: Option<ShareAnswer>,
}

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

struct Posted {
    id: u64,
    deadline: Instant,
    request: Takeover,
}

#[derive(Default)]
struct State {
    posted: Option<Posted>,
    next_id: u64,
    lapsed: Option<Lapsed>,
}

/// One session's slot, shared by cloning between its console thread and
/// the GUI.
#[derive(Clone)]
pub struct TakeoverSlot {
    state: Arc<Mutex<State>>,
    now: Clock,
}

impl Default for TakeoverSlot {
    fn default() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }
}

impl TakeoverSlot {
    /// With a clock of the caller's, for tests.
    pub fn with_clock(now: Clock) -> Self {
        Self { state: Default::default(), now }
    }

    /// Post a request, in place of any still pending, and start its deadline.
    pub fn post(&self, request: Takeover) {
        let deadline = (self.now)() + request.lasts;
        let id = {
            let mut st = self.state.lock().unwrap();
            st.next_id += 1;
            let id = st.next_id;
            st.posted = Some(Posted { id, deadline, request });
            id
        };
        let slot = self.clone();
        std::thread::spawn(move || loop {
            let left = deadline.saturating_duration_since((slot.now)());
            if left.is_zero() {
                slot.lapse(id);
                return;
            }
            if slot.state.lock().unwrap().posted.as_ref().map(|p| p.id) != Some(id) {
                return; // answered, withdrawn or replaced
            }
            std::thread::sleep(left.min(Duration::from_millis(50)));
        });
    }

    /// The deadline passed with request `id` unanswered.
    fn lapse(&self, id: u64) {
        let posted = {
            let mut st = self.state.lock().unwrap();
            if st.posted.as_ref().map(|p| p.id) != Some(id) {
                return;
            }
            st.posted.take().unwrap()
        };
        let answered = posted.request.on_timeout;
        if let Some(a) = answered {
            (posted.request.respond)(a);
        }
        self.state.lock().unwrap().lapsed = Some(Lapsed { user: posted.request.user, answered });
    }

    /// The BMC withdrew the request. Whether one was pending.
    pub fn withdraw(&self) -> bool {
        self.state.lock().unwrap().posted.take().is_some()
    }

    /// The request waiting for an answer, if any.
    pub fn pending(&self) -> Option<Pending> {
        let st = self.state.lock().unwrap();
        let p = st.posted.as_ref()?;
        let r = &p.request;
        Some(Pending {
            user: r.user.clone(),
            addr: r.addr.clone(),
            question: r.question.clone(),
            answers: r.answers.clone(),
            on_timeout: r.on_timeout,
            left: p.deadline.saturating_duration_since((self.now)()),
        })
    }

    /// Answer the pending request; the user it came from, or None when it
    /// had already ended.
    pub fn answer(&self, a: ShareAnswer) -> Option<String> {
        let posted = self.state.lock().unwrap().posted.take()?;
        (posted.request.respond)(a);
        Some(posted.request.user)
    }

    /// A request that ended unanswered since this was last asked.
    pub fn take_lapsed(&self) -> Option<Lapsed> {
        self.state.lock().unwrap().lapsed.take()
    }
}

/// Act on an AMI IVTP sharing message: post a request for the GUI to answer,
/// or say what happened to one. Shared by the Quanta and SP-X consoles.
pub fn ami_sharing(ev: crate::families::quanta::kvm::Sharing, slot: &TakeoverSlot,
                   notice: &Arc<Mutex<String>>, reply: &Sender<Vec<u8>>) {
    use crate::families::quanta::kvm::{sharing_reply, Sharing};
    match ev {
        Sharing::Request { user, addr, info, full_access } => {
            let who = if user.is_empty() { "Another user".to_string() } else { user.clone() };
            let (question, answers) = if full_access {
                (format!("{who} is viewing this console and asks for full control."),
                 vec![(ShareAnswer::Full, "Give them control"), (ShareAnswer::ViewOnly, "Keep control")])
            } else {
                (format!("{who} wants to use this console."),
                 vec![(ShareAnswer::Full, "Give full access"), (ShareAnswer::ViewOnly, "Let them view"),
                      (ShareAnswer::Deny, "Deny")])
            };
            let tx = reply.clone();
            slot.post(Takeover {
                user, addr, question, answers,
                // The vendor dialog's 30 seconds; the BMC withdraws it after that.
                lasts: Duration::from_secs(30),
                on_timeout: None,
                respond: Box::new(move |a| {
                    for p in sharing_reply(&info, a) { let _ = tx.send(p); }
                }),
            });
        }
        Sharing::Withdrawn => {
            if slot.withdraw() {
                *notice.lock().unwrap() = "the access request was withdrawn".into();
            }
        }
        Sharing::Waiting { user } => {
            *notice.lock().unwrap() = if user.is_empty() {
                "waiting for the current user to allow access…".into()
            } else {
                format!("waiting for {user} to allow access…")
            };
        }
        Sharing::Verdict(v) => *notice.lock().unwrap() = v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock that moves only when told to, in milliseconds.
    fn manual() -> (TakeoverSlot, Arc<AtomicU64>) {
        let start = Instant::now();
        let ms = Arc::new(AtomicU64::new(0));
        let at = ms.clone();
        (TakeoverSlot::with_clock(Arc::new(move || start + Duration::from_millis(at.load(Ordering::SeqCst)))), ms)
    }

    fn request(on_timeout: Option<ShareAnswer>, said: &Arc<Mutex<Vec<ShareAnswer>>>) -> Takeover {
        let said = said.clone();
        Takeover {
            user: "operator".into(),
            addr: "192.0.2.50".into(),
            question: "operator wants to take over this console.".into(),
            answers: vec![(ShareAnswer::Full, "Give it to them"), (ShareAnswer::Deny, "Keep it")],
            lasts: Duration::from_secs(10),
            on_timeout,
            respond: Box::new(move |a| said.lock().unwrap().push(a)),
        }
    }

    /// Wait, in real time, for the deadline thread to act.
    fn until(cond: impl Fn() -> bool) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the deadline thread never acted");
    }

    #[test]
    fn ilo_hands_the_console_over_at_its_deadline_with_nobody_drawing() {
        let (slot, ms) = manual();
        let said: Arc<Mutex<Vec<ShareAnswer>>> = Default::default();
        slot.post(request(Some(ShareAnswer::Full), &said));
        ms.store(9_900, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(150));
        assert!(said.lock().unwrap().is_empty(), "not before the deadline");
        assert_eq!(slot.pending().unwrap().left, Duration::from_millis(100));
        ms.store(10_000, Ordering::SeqCst);
        until(|| !said.lock().unwrap().is_empty());
        assert_eq!(*said.lock().unwrap(), [ShareAnswer::Full]);
        assert!(slot.pending().is_none());
        assert_eq!(slot.take_lapsed(), Some(Lapsed { user: "operator".into(), answered: Some(ShareAnswer::Full) }));
        assert_eq!(slot.take_lapsed(), None, "reported once");
    }

    #[test]
    fn an_ami_request_lapses_unanswered_and_an_answer_stops_the_clock() {
        let (slot, ms) = manual();
        let said: Arc<Mutex<Vec<ShareAnswer>>> = Default::default();
        slot.post(request(None, &said));
        ms.store(10_000, Ordering::SeqCst);
        until(|| slot.pending().is_none());
        assert!(said.lock().unwrap().is_empty(), "the BMC decides");
        assert_eq!(slot.take_lapsed().unwrap().answered, None);

        slot.post(request(Some(ShareAnswer::Full), &said));
        assert_eq!(slot.answer(ShareAnswer::Deny).as_deref(), Some("operator"));
        ms.store(30_000, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(*said.lock().unwrap(), [ShareAnswer::Deny], "answered once, by the user");
        assert!(slot.answer(ShareAnswer::Full).is_none());
        assert!(slot.take_lapsed().is_none());
    }

    #[test]
    fn a_withdrawn_or_replaced_request_never_fires() {
        let (slot, ms) = manual();
        let said: Arc<Mutex<Vec<ShareAnswer>>> = Default::default();
        slot.post(request(Some(ShareAnswer::Full), &said));
        assert!(slot.withdraw());
        assert!(!slot.withdraw());
        ms.store(5_000, Ordering::SeqCst);
        slot.post(request(Some(ShareAnswer::Full), &said));
        // The first one's deadline passes; the second's has 5 s to go.
        ms.store(12_000, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(150));
        assert!(said.lock().unwrap().is_empty());
        assert!(slot.pending().is_some());
        ms.store(15_000, Ordering::SeqCst);
        until(|| said.lock().unwrap().len() == 1);
    }
}
