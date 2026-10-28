//! The one writer of hosts.json in a running GUI, and its watch on the
//! configuration files.
//!
//! Every change goes through `hosts::edit_hosts`, which reads the file as it
//! is now under `hosts::locked`, changes it and writes it back: the GUI
//! holds its hosts for the whole run while `bmc-kvm route …` changes them on
//! disk, so it must never save its own copy over theirs. Hosts are matched
//! by canonical address (`net::same_address`), as the route table matches
//! them.
//!
//! The list a GUI shows is its own (it adds the command line's unsaved host
//! and the credentials typed for it); this holds what the file said.

use crate::hosts::{self, Host};
use std::time::{Duration, Instant, SystemTime};

pub struct Inventory {
    /// Why hosts.json could not be read, while it cannot. The list keeps
    /// the hosts last read, but nothing is routed or saved until it parses.
    error: Option<String>,
    /// `hosts::generation()` as of the last rebuild, and as last seen.
    generation: u64,
    seen_generation: u64,
    /// hosts.json, routes.json and groups.json's mtimes, read at most once
    /// a second, for changes another process made.
    mtimes: [Option<SystemTime>; 3],
    mtime_check: Instant,
    /// hosts.json changed on disk and has not been read again.
    stale: bool,
    /// The configuration error last reported, so that it is said once
    /// rather than on every rebuild while it stands.
    complaint: Option<String>,
}

fn mtimes() -> [Option<SystemTime>; 3] {
    [hosts::store_path(), crate::routes::routes_path(), crate::routes::groups_path()]
        .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
}

impl Inventory {
    /// Read hosts.json, and the hosts in it. Not `hosts::load`, which reads
    /// the ini when hosts.json does not parse: those hosts carry no routes,
    /// so a routed host would be probed directly.
    pub fn load() -> (Self, Vec<Host>) {
        let (hosts, error) = match hosts::try_load() {
            Ok(hosts) => (hosts, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let generation = hosts::generation();
        let inventory = Inventory {
            error,
            generation,
            seen_generation: generation,
            mtimes: mtimes(),
            mtime_check: Instant::now(),
            stale: false,
            complaint: None,
        };
        (inventory, hosts)
    }

    /// Why hosts.json cannot be read, if it cannot.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// `hosts` as the route table takes them: refused while the file is
    /// broken, since it may be where an address's route is.
    pub fn hosts_or_error<'a>(&'a self, hosts: &'a [Host]) -> Result<&'a [Host], &'a str> {
        self.error().map_or(Ok(hosts), Err)
    }

    /// Change hosts.json as it is on disk now, under the inventory lock, and
    /// return what was saved: see `hosts::edit_hosts`. Nothing is written
    /// while hosts.json does not parse.
    pub fn edit<T>(&mut self, change: impl FnOnce(&mut Vec<Host>) -> Result<T, String>) -> Result<(T, Vec<Host>), String> {
        hosts::edit_hosts(change)
    }

    /// Save freshly detected families: see [`record_families`].
    pub fn record_families(&mut self, changed: Vec<Host>, unsaved_cli: Option<&str>) -> Result<Vec<Host>, String> {
        self.edit(|on_disk| {
            record_families(on_disk, changed, unsaved_cli);
            Ok(())
        })
        .map(|((), saved)| saved)
    }

    /// Read hosts.json again after another process changed it. One that
    /// does not parse gives None and is remembered: the caller keeps the
    /// list as it was, but routes nothing.
    pub fn reload(&mut self) -> Option<Vec<Host>> {
        self.stale = false;
        match hosts::try_load() {
            Ok(hosts) => {
                self.error = None;
                Some(hosts)
            }
            Err(e) => {
                self.error = Some(e);
                None
            }
        }
    }

    /// Whether the configuration changed since the last `synced`: saved
    /// here (a route pinned from a connect thread included), or edited by
    /// another process (`bmc-kvm route …`, or by hand), which is noticed by
    /// mtime at most once a second. An edited hosts.json is also marked
    /// stale, to be read again with `reload` before the table is rebuilt.
    pub fn poll(&mut self) -> bool {
        self.seen_generation = hosts::generation();
        let mut changed = self.seen_generation != self.generation;
        if self.mtime_check.elapsed() >= Duration::from_secs(1) {
            self.mtime_check = Instant::now();
            let seen = mtimes();
            if seen != self.mtimes {
                self.stale |= seen[0] != self.mtimes[0];
                self.mtimes = seen;
                changed = true;
            }
        }
        changed
    }

    /// Whether hosts.json changed on disk and has not been read again.
    pub fn stale(&self) -> bool {
        self.stale
    }

    /// The table has been rebuilt for everything `poll` saw.
    pub fn synced(&mut self) {
        self.generation = self.seen_generation;
    }

    /// A configuration file that does not parse leaves hosts unable to
    /// connect: say which and why, once, and again only if that changes.
    /// Some(text) when there is something new to say.
    pub fn complain(
        &mut self,
        routes: &crate::routes::LoadedRoutes,
        groups: &crate::routes::LoadedGroups,
    ) -> Option<String> {
        let error = if let Some(e) = &self.error {
            Some(format!("{e}: no host will connect, and the inventory will not be saved, until it is fixed"))
        } else if let Err(e) = routes {
            Some(format!("{e}: hosts with a route will not connect until it is fixed"))
        } else {
            groups.as_ref().err().map(|e| {
                format!("{e}: hosts that take their group's route will not connect until it is fixed")
            })
        };
        let new = error.clone().filter(|e| Some(e) != self.complaint.as_ref());
        self.complaint = error;
        new
    }
}

/// Give hosts.json the families detected for `changed` and nothing else of
/// theirs: the rest of each host is as the file has it, so credentials typed
/// on the command line for a saved host stay off the disk. A host the file
/// lacks is added only if it is `unsaved_cli`, the command line's host never
/// saved, which a detected family has always added to the inventory; any
/// other was removed, here or elsewhere, and stays removed.
pub fn record_families(on_disk: &mut Vec<Host>, changed: Vec<Host>, unsaved_cli: Option<&str>) {
    for h in changed {
        match on_disk.iter_mut().find(|d| crate::net::same_address(&d.address, &h.address)) {
            Some(d) => (d.family, d.vendor) = (h.family, h.vendor),
            None if unsaved_cli.is_some_and(|a| crate::net::same_address(a, &h.address)) => on_disk.push(h),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_detected_family_adds_only_the_command_lines_unsaved_host() {
        let at = |a: &str| Host { address: a.into(), ..Default::default() };
        let mut on_disk = vec![Host { user: "saved".into(), password: "on disk".into(), ..at("10.20.1.11") }];
        let found = |h: Host| Host { family: "ilo4".into(), user: "typed".into(), password: "on the command line".into(), ..h };
        // The command line's credentials for a saved host stay off the disk.
        record_families(&mut on_disk, vec![found(at("10.20.1.11"))], Some("10.20.1.11"));
        assert_eq!((on_disk[0].family.as_str(), on_disk[0].user.as_str()), ("ilo4", "saved"));
        // A host removed elsewhere is not put back.
        record_families(&mut on_disk, vec![found(at("10.20.1.12"))], None);
        assert_eq!(on_disk.len(), 1);
        record_families(&mut on_disk, vec![found(at("10.20.1.12"))], Some("10.20.1.13"));
        assert_eq!(on_disk.len(), 1, "only the command line's host");
        // The command line's host, never saved, is added as it always was.
        record_families(&mut on_disk, vec![found(at("10.20.1.13"))], Some("10.20.1.13"));
        assert_eq!(on_disk.len(), 2);
    }

    #[test]
    fn a_family_finds_its_host_by_canonical_address() {
        let mut on_disk = vec![Host { address: "[FD00:0:0::5]".into(), ..Default::default() }];
        let found = Host { address: "fd00::5".into(), family: "idrac9".into(), ..Default::default() };
        record_families(&mut on_disk, vec![found], None);
        assert_eq!((on_disk.len(), on_disk[0].family.as_str()), (1, "idrac9"));
        assert_eq!(on_disk[0].address, "[FD00:0:0::5]", "the address is kept as the user typed it");
    }

    #[test]
    fn a_configuration_error_is_said_once_until_it_changes() {
        let mut inv = Inventory {
            error: Some("hosts.json: eof".into()),
            generation: 0,
            seen_generation: 0,
            mtimes: Default::default(),
            mtime_check: Instant::now(),
            stale: false,
            complaint: None,
        };
        let (routes, groups) = (Ok(Vec::new()), Ok(Default::default()));
        assert!(inv.complain(&routes, &groups).unwrap().starts_with("hosts.json: eof: no host will connect"));
        assert!(inv.complain(&routes, &groups).is_none(), "said once");
        inv.error = None;
        let broken: crate::routes::LoadedRoutes = Err("routes.json: eof".into());
        assert!(inv.complain(&broken, &groups).unwrap().contains("hosts with a route"));
        assert!(inv.complain(&routes, &groups).is_none(), "fixed: nothing to say");
        assert!(inv.complain(&broken, &groups).is_some(), "broken again: said again");
    }
}
