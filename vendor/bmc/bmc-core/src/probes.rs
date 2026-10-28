//! The inventory's background probes: what each host answered last, shared
//! by every view that labels a host, and the one place that starts a probe.

use crate::families::probe::{self, Probe};
use crate::hosts::{self, Host};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

/// Starts a probe of `address` with these credentials, reporting into the
/// map; `asked` when the user asked for it. `probe::spawn` but in tests.
pub type ProbeFn = Arc<dyn Fn(String, String, String, Arc<Mutex<HashMap<String, Probe>>>, bool) + Send + Sync>;

/// The probe results by address, shared by cloning. It dereferences to the
/// map's lock for reading.
#[derive(Clone)]
pub struct ProbeStore {
    map: Arc<Mutex<HashMap<String, Probe>>>,
    probe: ProbeFn,
}

impl Default for ProbeStore {
    fn default() -> Self {
        Self::with_probe(Arc::new(probe::spawn))
    }
}

impl Deref for ProbeStore {
    type Target = Mutex<HashMap<String, Probe>>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl ProbeStore {
    /// With a probe of the caller's, for tests.
    pub fn with_probe(probe: ProbeFn) -> Self {
        Self { map: Default::default(), probe }
    }

    /// The map itself, for code that reports into one of its own kind.
    pub fn shared(&self) -> &Arc<Mutex<HashMap<String, Probe>>> {
        &self.map
    }

    /// What `addr` answered last, or nothing yet.
    pub fn get(&self, addr: &str) -> Probe {
        self.map.lock().unwrap().get(addr).cloned().unwrap_or_default()
    }

    /// Probe `h` again in the background, with its saved credentials. It is
    /// background work: a route that refused it is not retried.
    pub fn refresh(&self, h: &Host) {
        let (u, p) = hosts::credentials_for(h);
        (self.probe)(h.address.clone(), u, p, self.map.clone(), false);
    }

    /// Forget what `h` answered and probe it afresh, so a board swapped
    /// behind a known address is not shown as the old one meanwhile.
    pub fn rediscover(&self, h: &Host) {
        self.map.lock().unwrap().remove(&h.address);
        self.refresh(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe that records who it was asked about and answers at once.
    fn fake() -> (ProbeStore, Arc<Mutex<Vec<(String, String, bool)>>>) {
        let asked: Arc<Mutex<Vec<(String, String, bool)>>> = Default::default();
        let log = asked.clone();
        let store = ProbeStore::with_probe(Arc::new(move |addr: String, user: String, _pass, map: Arc<Mutex<HashMap<String, Probe>>>, by_user| {
            log.lock().unwrap().push((addr.clone(), user, by_user));
            map.lock().unwrap().insert(addr, Probe { reachable: Some(true), ..Default::default() });
        }));
        (store, asked)
    }

    #[test]
    fn a_refresh_probes_with_the_hosts_own_credentials_as_background_work() {
        let (store, asked) = fake();
        let h = Host { address: "192.0.2.5".into(), user: "admin".into(), password: "pw".into(), ..Default::default() };
        store.refresh(&h);
        assert_eq!(*asked.lock().unwrap(), [("192.0.2.5".to_string(), "admin".to_string(), false)]);
        assert_eq!(store.get("192.0.2.5").reachable, Some(true));
        assert!(store.get("192.0.2.6").reachable.is_none(), "never probed: nothing");
    }

    #[test]
    fn rediscover_forgets_the_old_answer_first() {
        let asked: Arc<Mutex<Vec<String>>> = Default::default();
        let log = asked.clone();
        // A probe that has not answered yet, so what is left is what was kept.
        let store = ProbeStore::with_probe(Arc::new(move |addr: String, _u, _p, _map, _by_user| {
            log.lock().unwrap().push(addr);
        }));
        let h = Host { address: "192.0.2.7".into(), user: "u".into(), password: "p".into(), ..Default::default() };
        store.lock().unwrap().insert(h.address.clone(), Probe { model: Some("old board".into()), ..Default::default() });
        store.rediscover(&h);
        assert!(store.get(&h.address).model.is_none());
        assert_eq!(asked.lock().unwrap().len(), 1);
    }
}
