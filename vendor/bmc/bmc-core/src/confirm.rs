//! The single gate for actions that reach the running machine. Anything that
//! does — power, Ctrl+Alt+Del, which reboots most systems, a BMC reset — is
//! first asked about, and runs only with the kind a committed nonce hands
//! back. A GUI never decides on its own that the user said yes: it shows the
//! question, and on Yes commits the nonce it was given. A nonce works once
//! and not for long, so a stale or replayed answer cannot fire an action.

use crate::hosts::Host;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// An action that reaches the running machine, held until the user confirms it.
#[derive(Clone, Debug)]
pub enum ConfirmKind {
    Power { addr: String, code: u8 },
    /// Ctrl+Alt+Del: on most systems this reboots, so it is worth a question.
    CtrlAltDel,
    /// Resetting the controller drops every active management session.
    ResetBmc { host: Host },
    /// Removing inventory data should never be possible from an icon misclick.
    DeleteHost { address: String, label: String },
    /// Detaching media can interrupt an install or recovery operation.
    EjectMedia { image: String },
    /// Leaving a console with media attached also ejects that media.
    DisconnectWithMedia { host: String, image: String },
    /// Re-enumerating USB input briefly removes the remote keyboard and mouse.
    ReattachInput,
}

/// A question asked: 128 random bits, so one cannot be guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 16]);

impl Nonce {
    fn new() -> Self {
        let mut b = [0u8; 16];
        crate::rand::fill(&mut b);
        Nonce(b)
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// How long a question stays answerable. Long enough for anyone reading
/// the dialog; short enough that one left open on an unattended screen
/// does not stay armed.
pub const TTL: Duration = Duration::from_secs(120);

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The open questions, shared by cloning.
#[derive(Clone)]
pub struct Confirmations {
    pending: Arc<Mutex<HashMap<Nonce, (ConfirmKind, Instant)>>>,
    ttl: Duration,
    now: Clock,
}

impl Default for Confirmations {
    fn default() -> Self {
        Self::with_clock(TTL, Arc::new(Instant::now))
    }
}

impl Confirmations {
    /// With a clock of the caller's, for tests.
    pub fn with_clock(ttl: Duration, now: Clock) -> Self {
        Self { pending: Default::default(), ttl, now }
    }

    /// Ask about `kind`. The nonce is what the answer must carry.
    pub fn begin(&self, kind: ConfirmKind) -> Nonce {
        let now = (self.now)();
        let mut pending = self.pending.lock().unwrap();
        let ttl = self.ttl;
        pending.retain(|_, (_, asked)| now.saturating_duration_since(*asked) < ttl);
        let nonce = Nonce::new();
        pending.insert(nonce, (kind, now));
        nonce
    }

    /// The user said yes: the action to run, once. None for a nonce never
    /// issued, already used or cancelled, or older than the TTL.
    pub fn commit(&self, nonce: &Nonce) -> Option<ConfirmKind> {
        let (kind, asked) = self.pending.lock().unwrap().remove(nonce)?;
        ((self.now)().saturating_duration_since(asked) < self.ttl).then_some(kind)
    }

    /// The user said no, or the question went away.
    pub fn cancel(&self, nonce: &Nonce) {
        self.pending.lock().unwrap().remove(nonce);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock that moves only when told to.
    fn manual() -> (Confirmations, Arc<AtomicU64>) {
        let start = Instant::now();
        let secs = Arc::new(AtomicU64::new(0));
        let at = secs.clone();
        let clock: Clock = Arc::new(move || start + Duration::from_secs(at.load(Ordering::SeqCst)));
        (Confirmations::with_clock(Duration::from_secs(60), clock), secs)
    }

    #[test]
    fn a_nonce_works_once() {
        let (c, _) = manual();
        let n = c.begin(ConfirmKind::Power { addr: "192.0.2.1".into(), code: 1 });
        assert!(matches!(c.commit(&n), Some(ConfirmKind::Power { code: 1, .. })));
        assert!(c.commit(&n).is_none(), "a second yes does nothing");
    }

    #[test]
    fn an_expired_nonce_is_refused() {
        let (c, secs) = manual();
        let n = c.begin(ConfirmKind::CtrlAltDel);
        secs.store(59, Ordering::SeqCst);
        let fresh = c.begin(ConfirmKind::ReattachInput);
        secs.store(60, Ordering::SeqCst);
        assert!(c.commit(&n).is_none());
        assert!(matches!(c.commit(&fresh), Some(ConfirmKind::ReattachInput)));
    }

    #[test]
    fn an_unknown_or_cancelled_nonce_is_refused() {
        let (c, _) = manual();
        let other = Confirmations::default();
        let theirs = other.begin(ConfirmKind::CtrlAltDel);
        assert!(c.commit(&theirs).is_none(), "issued by another gate");
        let n = c.begin(ConfirmKind::CtrlAltDel);
        c.cancel(&n);
        assert!(c.commit(&n).is_none());
        assert_ne!(c.begin(ConfirmKind::CtrlAltDel), c.begin(ConfirmKind::CtrlAltDel));
        assert_eq!(theirs.to_string().len(), 32);
    }
}
