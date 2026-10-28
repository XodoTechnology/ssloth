//! How the services tell a front end that something happened off its thread.
//! A service raises an `Event` through the `EventSink` it was given; the GUI's
//! sink records it where its views already look and asks for a repaint, so a
//! result shows the moment it lands rather than at the next mouse movement.
//!
//! Only what the services raise is here. A front end that needs more grows
//! the enum with the service that raises it.

use std::sync::{Arc, Mutex};

/// Something a service did that a front end shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A console connect has its result, whichever way it went.
    ConnectFinished { host: String },
    /// A console's liveness dropped. `id` is the `SessionManager`'s; its close
    /// is already under way.
    SessionEnded { id: u64, host: String },
    /// A background action's outcome, for the status line.
    Notice(String),
    /// What a close or a failed connect could not undo, one line naming the
    /// host: an iDRAC session left to time out, a BMC clock left rolled back.
    Problem(String),
    /// A mount on `host` finished attaching, or failed to.
    MountChanged { host: String },
}

/// Where a service's events go. Called from any thread.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

/// The sink for code that has nobody to tell.
pub struct Discard;

impl EventSink for Discard {
    fn emit(&self, _: Event) {}
}

/// Keeps every event, for tests.
#[derive(Clone, Default)]
pub struct Recorder(pub Arc<Mutex<Vec<Event>>>);

impl Recorder {
    pub fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
}

impl EventSink for Recorder {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

pub type Sink = Arc<dyn EventSink>;
