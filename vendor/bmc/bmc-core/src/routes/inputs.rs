//! What the route table is built from in a GUI: the files as read, the
//! command line's --via or --direct for its host, and hosts probed before
//! they are saved, routed as they will be once saved.

use crate::families::probe::Probe;
use crate::hosts::Host;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A host probed before it is saved: the host editor's Probe BMC and its
/// Discovery step, and the import page's Discover hosts. Its address is not
/// in the inventory, so the table would send it direct, with the typed
/// credentials, wherever its group's route says it must not go.
pub struct Provisional {
    address: String,
    chain: crate::net::Chain,
    /// The editor's (else the import page's): kept while that is open.
    editor: bool,
    /// Where its probe reports, so that it is kept while that runs.
    probes: Arc<Mutex<HashMap<String, Probe>>>,
}

impl Provisional {
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn chain(&self) -> &crate::net::Chain {
        &self.chain
    }
    /// Whether it is still needed: its window is open, or its probe runs.
    fn held(&self, editing: bool, importing: bool) -> bool {
        (if self.editor { editing } else { importing })
            || self.probes.lock().unwrap().get(&self.address).is_some_and(|pr| pr.checking)
    }
}

/// Drop the entries nothing needs any more; whether any went.
pub fn let_go(held: &mut Vec<Provisional>, editing: bool, importing: bool) -> bool {
    let before = held.len();
    held.retain(|p| p.held(editing, importing));
    held.len() != before
}

/// What the route table is built from: each file as it was read, or why it
/// could not be, and the command line's --via or --direct for its host.
#[derive(Clone, Copy)]
pub struct RouteInputs<'a> {
    pub hosts: Result<&'a [Host], &'a str>,
    pub groups: &'a crate::routes::LoadedGroups,
    pub routes: &'a crate::routes::LoadedRoutes,
    pub forced: Option<&'a (String, String)>,
}

/// Route `host`, not saved yet, as it will be once saved, before it is
/// probed into `probes`; or say why it cannot be.
///
/// An address the inventory already holds keeps the route the table gives
/// it: a draft must not reroute a saved host's other work. So does every
/// address while hosts.json does not parse, which is refused: the file may
/// be where the address's route is. A command line's --via or --direct for
/// the address still wins, as it will after the save.
pub fn route_unsaved(
    held: &mut Vec<Provisional>,
    host: &Host,
    editor: bool,
    probes: &Arc<Mutex<HashMap<String, Probe>>>,
    inputs: RouteInputs,
) -> Result<(), String> {
    let saved = inputs.hosts?;
    if saved.iter().any(|h| crate::net::same_address(&h.address, &host.address)) {
        return crate::net::chain_for(&host.address).map(|_| ());
    }
    let own = crate::routes::table_loaded(std::slice::from_ref(host), inputs.groups, inputs.routes)
        .chain_for(&host.address);
    let only = RouteInputs { hosts: Ok(&[]), ..inputs };
    let chain = route_table(only, &[(host.address.clone(), own)]).chain_for(&host.address);
    // At once, for the probe about to start; and kept, so that every
    // rebuild of the table until it is let go has it too. In place of the
    // same window's earlier entry for the address, not beside it.
    crate::net::set_route(&host.address, chain.clone());
    held.retain(|p| p.editor != editor || !crate::net::same_address(&p.address, &host.address));
    held.push(Provisional { address: host.address.clone(), chain: chain.clone(), editor, probes: probes.clone() });
    chain.map(|_| ())
}

/// `net`'s table for the inventory, each file as it was read or why it
/// could not be. On top of it, hosts being probed before they are saved, as
/// they will be routed once they are; and the host given on the command line,
/// sent the way its --via or --direct said. That host only: the rest of the
/// inventory is probed with its credentials as soon as the window opens,
/// and must go the way each host's own route says.
pub fn route_table(inputs: RouteInputs, provisional: &[(String, crate::net::Chain)]) -> crate::net::Table {
    let RouteInputs { hosts, groups, routes, forced } = inputs;
    let mut t = match hosts {
        Ok(hosts) => {
            let mut t = crate::routes::table_loaded(hosts, groups, routes);
            // Only for addresses the inventory does not hold.
            for (address, chain) in provisional {
                if !hosts.iter().any(|h| crate::net::same_address(&h.address, address)) {
                    t.set(address, chain.clone());
                }
            }
            t
        }
        // Which hosts have routes is in the file that would not parse, so no
        // host can be taken to have none, a draft's included.
        Err(e) => {
            let mut t = crate::net::Table::default();
            t.unlisted(Err(e.to_string()));
            t
        }
    };
    if let Some((address, route)) = forced {
        t.set(address, crate::routes::route_chain_loaded(route, routes));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts;
    use crate::routes::{Kind, Route};

    fn inputs<'a>(
        hosts: Result<&'a [Host], &'a str>,
        groups: &'a crate::routes::LoadedGroups,
        routes: &'a crate::routes::LoadedRoutes,
        forced: Option<&'a (String, String)>,
    ) -> RouteInputs<'a> {
        RouteInputs { hosts, groups, routes, forced }
    }

    #[test]
    fn a_forced_route_reaches_the_host_it_was_given_for_and_no_other() {
        let hosts: Vec<Host> = ["10.20.1.11", "10.20.1.12"]
            .iter()
            .map(|a| Host { address: (*a).into(), ..Default::default() })
            .collect();
        let routes = vec![Route { name: "jump".into(), kind: Kind::Socks5, host: "192.0.2.1".into(), port: 1080, ..Default::default() }];
        let forced = ("10.20.1.11".to_string(), "jump".to_string());
        let t = route_table(inputs(Ok(&hosts), &Ok(Default::default()), &Ok(routes.clone()), Some(&forced)), &[]);
        assert_eq!(t.chain_for("10.20.1.11").unwrap()[0].name, "jump");
        assert!(t.chain_for("10.20.1.12").unwrap().is_empty(), "the rest of the inventory keeps its own route");
        // A host that is not in the inventory yet, as `bmc-kvm <host>` allows.
        let forced = ("10.20.1.13".to_string(), "jump".to_string());
        let t = route_table(inputs(Ok(&hosts), &Ok(Default::default()), &Ok(routes.clone()), Some(&forced)), &[]);
        assert_eq!(t.chain_for("10.20.1.13").unwrap().len(), 1);
        assert!(t.chain_for("10.20.1.11").unwrap().is_empty());
        let direct = ("10.20.1.11".to_string(), crate::routes::DIRECT.to_string());
        let mut routed = hosts.clone();
        routed[0].route = "jump".into();
        let t = route_table(inputs(Ok(&routed), &Ok(Default::default()), &Ok(routes.clone()), Some(&direct)), &[]);
        assert!(t.chain_for("10.20.1.11").unwrap().is_empty(), "--direct overrides the host's own route");
    }

    #[test]
    fn a_host_probed_before_it_is_saved_goes_the_way_its_group_will_send_it() {
        let routes = Ok(vec![Route { name: "c2-jump".into(), kind: Kind::Socks5, host: "192.0.2.1".into(), port: 1080, ..Default::default() }]);
        let mut groups = crate::routes::Groups::new();
        groups.insert("London / Lab".into(), crate::routes::GroupSettings { route: "c2-jump".into() });
        let groups = Ok(groups);
        let probes: Arc<Mutex<HashMap<String, Probe>>> = Default::default();
        let mut held = Vec::new();
        let draft = |address: &str| Host { address: address.into(), group: "London/Lab".into(), ..Default::default() };

        route_unsaved(&mut held, &draft("c2-unsaved.test"), true, &probes, inputs(Ok(&[]), &groups, &routes, None)).unwrap();
        assert_eq!(crate::net::chain_for("c2-unsaved.test").unwrap()[0].name, "c2-jump", "at once");
        // And every rebuild of the table while it is held.
        let pairs: Vec<_> = held.iter().map(|p| (p.address.clone(), p.chain.clone())).collect();
        let t = route_table(inputs(Ok(&[]), &groups, &routes, None), &pairs);
        assert_eq!(t.chain_for("c2-unsaved.test").unwrap()[0].name, "c2-jump");

        // A groups.json that does not parse: not probed, and not direct.
        let broken = Err("groups.json: eof".to_string());
        let e = route_unsaved(&mut held, &draft("c2-broken.test"), false, &probes, inputs(Ok(&[]), &broken, &routes, None)).unwrap_err();
        assert_eq!(e, "groups.json: eof");
        assert!(crate::net::chain_for("c2-broken.test").is_err());

        // Let go of once its window has closed and its probe has finished,
        // and not before: the probe connects more than once.
        let editor = held.iter().find(|p| p.address == "c2-unsaved.test").unwrap();
        assert!(editor.held(true, false) && !editor.held(false, true));
        probes.lock().unwrap().insert("c2-unsaved.test".into(), Probe { checking: true, ..Default::default() });
        assert!(editor.held(false, false), "the window closed, but the probe still runs");

        // The command line's --direct for the address still wins.
        let direct = ("c2-forced.test".to_string(), crate::routes::DIRECT.to_string());
        route_unsaved(&mut held, &draft("c2-forced.test"), true, &probes, inputs(Ok(&[]), &groups, &routes, Some(&direct))).unwrap();
        assert!(crate::net::chain_for("c2-forced.test").unwrap().is_empty());
    }

    #[test]
    fn an_inventory_that_does_not_parse_routes_nothing_but_what_was_named() {
        let routes = vec![Route { name: "jump".into(), kind: Kind::Socks5, host: "192.0.2.1".into(), port: 1080, ..Default::default() }];
        let forced = ("10.20.1.11".to_string(), "jump".to_string());
        let probing = [("10.20.1.13".to_string(), Ok(Vec::new()))];
        let t = route_table(inputs(Err("hosts.json: expected value"), &Ok(Default::default()), &Ok(routes), Some(&forced)), &probing);
        assert_eq!(t.chain_for("10.20.1.12").unwrap_err(), "hosts.json: expected value", "not direct");
        assert_eq!(t.chain_for("10.20.1.11").unwrap()[0].name, "jump", "the command line said which way");
        assert!(t.chain_for("10.20.1.13").is_err(), "nor is a host being added, which the file may hold");
    }

    #[test]
    fn a_draft_never_reroutes_a_saved_host_or_a_broken_inventory() {
        let routes = Ok(vec![Route { name: "ci1-jump".into(), kind: Kind::Socks5, host: "192.0.2.1".into(), port: 1080, ..Default::default() }]);
        let groups = Ok(Default::default());
        let saved = vec![Host { address: "ci1-saved.test".into(), route: "ci1-jump".into(), ..Default::default() }];
        crate::net::set_route("ci1-saved.test", route_table(inputs(Ok(&saved), &groups, &routes, None), &[]).chain_for("ci1-saved.test"));
        let probes: Arc<Mutex<HashMap<String, Probe>>> = Default::default();
        let mut held = Vec::new();

        // Editing the saved host into "direct" does not send its probe, or
        // anything else of it, direct before the save.
        let draft = Host { address: "CI1-SAVED.test".into(), route: crate::routes::DIRECT.into(), ..Default::default() };
        route_unsaved(&mut held, &draft, true, &probes, inputs(Ok(&saved), &groups, &routes, None)).unwrap();
        assert!(held.is_empty(), "nothing held over a saved address");
        assert_eq!(crate::net::chain_for("ci1-saved.test").unwrap()[0].name, "ci1-jump");
        // Nor would a rebuild let an entry for it through.
        let pairs = [("ci1-saved.test".to_string(), Ok(Vec::new()))];
        let t = route_table(inputs(Ok(&saved), &groups, &routes, None), &pairs);
        assert_eq!(t.chain_for("ci1-saved.test").unwrap()[0].name, "ci1-jump");

        // While hosts.json does not parse, no draft is probed.
        let fresh = Host { address: "ci1-new.test".into(), ..Default::default() };
        let e = route_unsaved(&mut held, &fresh, true, &probes, inputs(Err("hosts.json: eof"), &groups, &routes, None))
            .unwrap_err();
        assert_eq!(e, "hosts.json: eof");
        assert!(held.is_empty());

        // Probing the same address again replaces its entry.
        for _ in 0..3 {
            route_unsaved(&mut held, &fresh, false, &probes, inputs(Ok(&saved), &groups, &routes, None)).unwrap();
        }
        assert_eq!(held.len(), 1, "one entry per address, not one per Discover");
    }

    #[test]
    fn an_abandoned_import_lets_its_routes_go() {
        let routes = Ok(Vec::new());
        let groups = Ok(Default::default());
        let probes: Arc<Mutex<HashMap<String, Probe>>> = Default::default();
        let mut held = Vec::new();
        for a in ["ci3-a.test", "ci3-b.test"] {
            let h = Host { address: a.into(), ..Default::default() };
            route_unsaved(&mut held, &h, false, &probes, inputs(Ok(&[]), &groups, &routes, None)).unwrap();
        }
        probes.lock().unwrap().insert("ci3-b.test".into(), Probe { checking: true, ..Default::default() });
        assert!(!let_go(&mut held, false, true), "kept while the import page is on screen");
        // The user went elsewhere: sync_routes counts the page as closed.
        assert!(let_go(&mut held, false, false));
        assert_eq!(held.iter().map(|p| p.address.as_str()).collect::<Vec<_>>(), ["ci3-b.test"], "until its probe ends");
        probes.lock().unwrap().get_mut("ci3-b.test").unwrap().checking = false;
        assert!(let_go(&mut held, false, false) && held.is_empty());
    }

    #[test]
    fn a_routes_json_that_does_not_parse_stops_the_hosts_that_name_a_route() {
        let mut hosts: Vec<Host> = ["10.20.1.11", "10.20.1.12"]
            .iter()
            .map(|a| Host { address: (*a).into(), ..Default::default() })
            .collect();
        hosts[0].route = "jump".into();
        let t = route_table(inputs(Ok(&hosts), &Ok(Default::default()), &Err("routes.json: eof".into()), None), &[]);
        assert_eq!(t.chain_for("10.20.1.11").unwrap_err(), "routes.json: eof");
        assert!(t.chain_for("10.20.1.12").unwrap().is_empty());
    }

    #[test]
    fn a_route_given_to_a_host_in_hosts_json_meanwhile_reaches_the_table() {
        crate::net::ssh::testing::isolate_config();
        let _turn = hosts::file_turn();
        let jump = Route { name: "c3-jump".into(), kind: Kind::Socks5, host: "192.0.2.1".into(), port: 1080, ..Default::default() };
        crate::routes::edit_routes(|all| {
            all.retain(|r| r.name != jump.name);
            all.push(jump.clone());
            Ok(())
        })
        .unwrap();
        // What sync_routes builds once it has read the files again.
        let read = || match hosts::try_load() {
            Ok(h) => route_table(inputs(Ok(&h), &crate::routes::try_load_groups(), &crate::routes::try_load_routes(), None), &[]),
            Err(e) => route_table(inputs(Err(&e), &crate::routes::try_load_groups(), &crate::routes::try_load_routes(), None), &[]),
        };
        let mut host = Host { address: "10.20.1.31".into(), ..Default::default() };
        hosts::save(std::slice::from_ref(&host)).unwrap();
        assert!(read().chain_for("10.20.1.31").unwrap().is_empty());
        // `bmc-kvm route host 10.20.1.31 c3-jump`, or a hand edit.
        host.route = jump.name.clone();
        hosts::save(&[host]).unwrap();
        assert_eq!(read().chain_for("10.20.1.31").unwrap()[0].name, "c3-jump");
        // And a typo in it stops the host rather than sending it direct.
        std::fs::write(hosts::store_path(), "[{\"address\": ").unwrap();
        assert!(read().chain_for("10.20.1.31").unwrap_err().contains("hosts.json"));
        std::fs::remove_file(hosts::store_path()).unwrap();
    }
}
