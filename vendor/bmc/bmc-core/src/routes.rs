//! Network routes: the SOCKS5 proxies and SSH jump hosts a BMC is reached
//! through, and which host uses which. A route is defined once, by name. A
//! group can name one as its default, which its hosts inherit through parent
//! groups unless a host names its own or opts out with `direct`. This module
//! is the data and the rules; `net` is the transport.

pub mod inputs;

use crate::hosts::{self, Host};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The `route` value that means "no route", stopping inheritance. Reserved,
/// so no route may be called this.
pub const DIRECT: &str = "direct";
/// What `route host` and `route group` take for "take the group's route",
/// which is stored as an empty `route`. Reserved too, or a route of that
/// name could not be chosen there.
pub const INHERIT: &str = "inherit";
/// Chains longer than this are refused: a real path is one or two hops, and
/// a deeper one is a configuration mistake.
pub const MAX_HOPS: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Socks5,
    Ssh,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    #[default]
    Agent,
    Key,
    Password,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Route {
    pub name: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// SSH only. A SOCKS5 route authenticates with `user`/`secret` when it
    /// has a user.
    pub auth: Auth,
    pub key_file: String,
    /// The SOCKS5 or SSH password, or the key's passphrase.
    pub secret: String,
    /// SSH only: the pinned `SHA256:` fingerprint, empty until first contact.
    pub host_key: String,
    /// The route this one's own server is reached through, or empty.
    pub via: String,
}

impl Route {
    pub fn default_port(kind: Kind) -> u16 {
        match kind {
            Kind::Socks5 => 1080,
            Kind::Ssh => 22,
        }
    }
    /// How errors and the GUI name this hop: `london-jump (ssh ops@jump:22)`.
    pub fn describe(&self) -> String {
        let kind = match self.kind {
            Kind::Socks5 => "socks5",
            Kind::Ssh => "ssh",
        };
        let user = if self.user.is_empty() { String::new() } else { format!("{}@", self.user) };
        format!("{} ({kind} {user}{}:{})", self.name, self.host, self.port)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GroupSettings {
    /// As `Host::route`: empty inherits, `direct` stops inheritance.
    pub route: String,
}

/// Group settings keyed by the group path exactly as `hosts::location` prints it.
pub type Groups = BTreeMap<String, GroupSettings>;

/// groups.json as read: its groups, or why it could not be read. The error
/// is kept rather than taken for "no groups", which would send every host
/// that inherits a group's route direct over a stray comma.
pub type LoadedGroups = Result<Groups, String>;

/// Where a host's route was decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Host,
    Group(String),
    Default,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// Hops in the order they are dialled, from this machine outwards; empty
    /// means a direct connection.
    pub chain: Vec<Route>,
    pub source: Source,
}

impl Resolved {
    /// What an "Inherit" choice shows: `london-jump, from London`, or `direct`.
    pub fn summary(&self) -> String {
        let name = self.chain.last().map_or(DIRECT, |r| r.name.as_str());
        match &self.source {
            Source::Group(g) => format!("{name}, from {g}"),
            Source::Host | Source::Default => name.to_owned(),
        }
    }
}

pub fn routes_path() -> PathBuf {
    hosts::config_dir().join("routes.json")
}
pub fn groups_path() -> PathBuf {
    hosts::config_dir().join("groups.json")
}

/// `path`'s contents through `parse`; nothing when there is no such file, and
/// an error naming the file when it cannot be read or does not parse.
fn try_load<T: Default>(path: PathBuf, parse: impl FnOnce(&[u8]) -> Result<T, String>) -> Result<T, String> {
    match std::fs::read(&path) {
        Ok(b) => parse(&b).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// routes.json as read: its routes, or why it could not be read.
pub type LoadedRoutes = Result<Vec<Route>, String>;

/// The saved routes. A file that exists and does not parse is an error, not
/// no routes: the CLI would list nothing and report success, and the GUI
/// would send the user looking for a route that is there.
pub fn try_load_routes() -> LoadedRoutes {
    try_load(routes_path(), |b| serde_json::from_slice(b).map_err(|e| e.to_string()))
}
pub fn save_routes(routes: &[Route]) -> std::io::Result<()> {
    hosts::write_inventory(&routes_path(), routes)
}
/// groups.json, or why it cannot be used. There is no lenient twin, as
/// there is for routes: a group's route is lost silently when its file is,
/// where a host's names a route that is then missing, and fails.
pub fn try_load_groups() -> LoadedGroups {
    try_load(groups_path(), parse_groups)
}
/// Keys are normalised as `hosts::location` prints a path, so a hand-written
/// `London/Lab` still finds its hosts. Two keys for one group are refused:
/// either could be the one meant.
fn parse_groups(b: &[u8]) -> Result<Groups, String> {
    let raw: Groups = serde_json::from_slice(b).map_err(|e| e.to_string())?;
    let mut groups = Groups::new();
    for (key, settings) in raw {
        let path = hosts::group_path(&key);
        if groups.insert(path.clone(), settings).is_some() {
            return Err(format!("{key:?} is group {path:?} again, under another spelling"));
        }
    }
    Ok(groups)
}
pub fn save_groups(groups: &Groups) -> std::io::Result<()> {
    hosts::write_inventory(&groups_path(), groups)
}

/// The hops behind route `name`, outermost first: `name`'s `via`, that
/// route's `via`, and so on, reversed into dialling order.
pub fn chain(name: &str, routes: &[Route]) -> Result<Vec<Route>, String> {
    let mut chain: Vec<Route> = Vec::new();
    let mut next = name.trim().to_owned();
    while !next.is_empty() {
        if chain.iter().any(|r| r.name == next) {
            return Err(format!("route {name} loops back through {next}"));
        }
        if chain.len() == MAX_HOPS {
            return Err(format!("route {name} has more than {MAX_HOPS} hops"));
        }
        let r = routes
            .iter()
            .find(|r| r.name == next)
            .ok_or_else(|| format!("no route named {next}"))?;
        next = r.via.trim().to_owned();
        chain.push(r.clone());
    }
    chain.reverse();
    Ok(chain)
}

fn named(name: &str, routes: &[Route], source: Source) -> Result<Resolved, String> {
    if name.eq_ignore_ascii_case(DIRECT) {
        return Ok(Resolved { chain: Vec::new(), source });
    }
    Ok(Resolved { chain: chain(name, routes)?, source })
}

/// The hops a `--via <name>` or `--direct` asks for.
pub fn route_chain(name: &str, routes: &[Route]) -> Result<Vec<Route>, String> {
    named(name, routes, Source::Host).map(|r| r.chain)
}

/// `route_chain` against routes.json as loaded: a route asked for from a
/// file that does not parse fails with the file's error, not as missing.
pub fn route_chain_loaded(name: &str, routes: &LoadedRoutes) -> Result<Vec<Route>, String> {
    match routes {
        Ok(all) => route_chain(name, all),
        Err(e) => route_chain(name, &[]).map_err(|_| e.clone()),
    }
}

/// `London / Compute / Prod`, then `London / Compute`, then `London`.
fn ancestors(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split(" / ").collect();
    (1..=parts.len()).rev().map(|n| parts[..n].join(" / ")).collect()
}

/// The route `host` is reached through, and where that was decided.
pub fn resolve(host: &Host, groups: &Groups, routes: &[Route]) -> Result<Resolved, String> {
    let own = host.route.trim();
    if !own.is_empty() {
        return named(own, routes, Source::Host);
    }
    for group in ancestors(&hosts::location(host)) {
        let r = groups.get(&group).map_or("", |g| g.route.trim());
        if !r.is_empty() {
            return named(r, routes, Source::Group(group));
        }
    }
    Ok(Resolved { chain: Vec::new(), source: Source::Default })
}

/// `resolve` against groups.json as loaded. A host that names its own route,
/// or `direct`, never reads the groups; one that inherits is given the
/// file's error, since which route its groups name cannot be known.
pub fn resolve_loaded(host: &Host, groups: &LoadedGroups, routes: &[Route]) -> Result<Resolved, String> {
    match groups {
        Ok(g) => resolve(host, g, routes),
        Err(e) if host.route.trim().is_empty() => Err(e.clone()),
        Err(_) => resolve(host, &Groups::new(), routes),
    }
}

/// What `host` would get if it named no route itself: the Inherit choice.
pub fn inherited(host: &Host, groups: &Groups, routes: &[Route]) -> Result<Resolved, String> {
    let mut h = host.clone();
    h.route.clear();
    resolve(&h, groups, routes)
}

/// What group `path` would get from its parents: its own Inherit choice.
pub fn group_inherited(path: &str, groups: &Groups, routes: &[Route]) -> Result<Resolved, String> {
    for group in ancestors(path).into_iter().skip(1) {
        let r = groups.get(&group).map_or("", |g| g.route.trim());
        if !r.is_empty() {
            return named(r, routes, Source::Group(group));
        }
    }
    Ok(Resolved { chain: Vec::new(), source: Source::Default })
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:".contains(c))
}

/// Refuse a route that cannot be saved beside `others`, the saved routes
/// without this one's old self.
pub fn validate(route: &Route, others: &[Route]) -> Result<(), String> {
    let name = route.name.trim();
    if name.is_empty() {
        return Err("A route needs a name.".into());
    }
    if name.eq_ignore_ascii_case(DIRECT) {
        return Err("\"direct\" is reserved: it means no route.".into());
    }
    if name.eq_ignore_ascii_case(INHERIT) {
        return Err("\"inherit\" is reserved: it means the group's route.".into());
    }
    // Names are typed on command lines, after options and among them.
    if name.starts_with('-') || name.contains(char::is_whitespace) {
        return Err(format!("{name:?} cannot be a route's name: it may not start with '-' or hold spaces."));
    }
    if others.iter().any(|r| r.name.eq_ignore_ascii_case(name)) {
        return Err(format!("There is already a route called {name}."));
    }
    if !valid_host(route.host.trim()) {
        return Err("Enter the proxy or jump host's address, without a scheme or port.".into());
    }
    if route.port == 0 {
        return Err("Enter a port.".into());
    }
    if route.kind == Kind::Ssh && route.user.trim().is_empty() {
        return Err("An SSH route needs a user name.".into());
    }
    // A proxy is sent a password only along with a user name.
    if route.kind == Kind::Socks5 && route.user.trim().is_empty() && !route.secret.is_empty() {
        return Err("A SOCKS5 password needs a user name: give the address as user@host.".into());
    }
    if route.kind == Kind::Ssh && route.auth == Auth::Key && route.key_file.trim().is_empty() {
        return Err("Choose the key file.".into());
    }
    let mut all = others.to_vec();
    all.push(route.clone());
    chain(name, &all).map(drop)
}

/// Who still uses route `name`. A delete is refused while this is not empty.
pub fn users(name: &str, hosts: &[Host], groups: &Groups, routes: &[Route]) -> Vec<String> {
    let mut out: Vec<String> =
        hosts.iter().filter(|h| h.route == name).map(|h| format!("host {}", h.label())).collect();
    out.extend(groups.iter().filter(|(_, g)| g.route == name).map(|(p, _)| format!("group {p}")));
    out.extend(routes.iter().filter(|r| r.via == name).map(|r| format!("route {}", r.name)));
    out
}

/// Rename a route everywhere it is referenced. The caller saves all three.
pub fn rename(old: &str, new: &str, hosts: &mut [Host], groups: &mut Groups, routes: &mut [Route]) {
    for h in hosts.iter_mut().filter(|h| h.route == old) {
        h.route = new.into();
    }
    for g in groups.values_mut().filter(|g| g.route == old) {
        g.route = new.into();
    }
    for r in routes.iter_mut() {
        if r.name == old {
            r.name = new.into();
        }
        if r.via == old {
            r.via = new.into();
        }
    }
}

/// Read routes.json, change it and write it back, as one step under the
/// inventory lock: connect threads pin keys and save secrets while the user
/// edits, perhaps from another bmc-kvm, and a write made from a stale read
/// would undo another's. A change that returns an error writes nothing; so
/// does a routes.json that does not parse, which is reported rather than
/// replaced.
pub fn edit_routes<T>(change: impl FnOnce(&mut Vec<Route>) -> Result<T, String>) -> Result<T, String> {
    hosts::locked(|| {
        let mut routes = try_load_routes()?;
        let out = change(&mut routes)?;
        save_routes(&routes).map_err(|e| format!("{}: {e}", routes_path().display()))?;
        Ok(out)
    })?
}

fn update_route(name: &str, change: impl FnOnce(&mut Route)) -> Result<(), String> {
    edit_routes(|routes| {
        let r = routes.iter_mut().find(|r| r.name == name).ok_or_else(|| format!("no route named {name}"))?;
        change(r);
        Ok(())
    })
}

/// Whether `fp` is the form ssh.rs prints and compares: `SHA256:` and the 43
/// unpadded base64 characters of a SHA-256 digest.
pub fn valid_fingerprint(fp: &str) -> bool {
    fp.strip_prefix("SHA256:").is_some_and(|b| {
        b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    })
}

/// Remember a jump host's key once it has been trusted.
pub fn pin_host_key(name: &str, fingerprint: &str) -> Result<(), String> {
    update_route(name, |r| r.host_key = fingerprint.into())
}

/// Keep a secret the user typed at a prompt and asked to save.
pub fn save_secret(name: &str, secret: &str) -> Result<(), String> {
    update_route(name, |r| r.secret = secret.into())
}

/// The table `net` dials by: every inventory address mapped to its chain.
/// One BMC listed twice (`fd00::5` and `FD00:0::5`) with different routes
/// gets neither: which was meant cannot be known, and the last listed
/// would otherwise win without a word.
pub fn table(hosts: &[Host], groups: &LoadedGroups, routes: &[Route]) -> crate::net::Table {
    let mut t = crate::net::Table::default();
    let mut seen: std::collections::HashMap<String, (String, crate::net::Chain)> = Default::default();
    for h in hosts {
        let mut chain = resolve_loaded(h, groups, routes).map(|r| r.chain);
        let key = crate::net::addr_key(&h.address);
        if let Some((first, earlier)) = seen.get(&key) {
            if *earlier != chain {
                chain = Err(format!("{first} is listed twice with different routes"));
            }
        }
        seen.entry(key).or_insert_with(|| (h.address.clone(), chain.clone())).1 = chain.clone();
        t.set(&h.address, chain);
    }
    t
}

/// `table` against routes.json as loaded. A file that does not parse gives
/// every host that names a route, itself or through its group, the file's
/// error rather than "no route named …", which would send the user looking
/// for a route that is there; a host that goes direct still does.
pub fn table_loaded(hosts: &[Host], groups: &LoadedGroups, routes: &LoadedRoutes) -> crate::net::Table {
    let e = match routes {
        Ok(all) => return table(hosts, groups, all),
        Err(e) => e,
    };
    let mut t = table(hosts, groups, &[]);
    for h in hosts {
        // groups.json's own error stands: whether the host needs a route
        // at all is in that file.
        if t.chain_for(&h.address).is_err_and(|why| groups.as_ref().err() != Some(&why)) {
            t.set(&h.address, Err(e.clone()));
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_must_be_sha256_base64() {
        assert!(valid_fingerprint("SHA256:mpqLvnyKWXVAxgjB1CgmafTUVxSGmZUUGCP4LPDz38M"));
        assert!(!valid_fingerprint("SHA256:short"));
        assert!(!valid_fingerprint("MD5:mpqLvnyKWXVAxgjB1CgmafTUVxSGmZUUGCP4LPDz38M"));
        assert!(!valid_fingerprint("SHA256:mpqLvnyKWXVAxgjB1CgmafTUVxSGmZUUGCP4LPDz38="));
    }

    fn route(name: &str, kind: Kind, via: &str) -> Route {
        Route {
            name: name.into(),
            kind,
            host: format!("{name}.example"),
            port: Route::default_port(kind),
            user: "ops".into(),
            via: via.into(),
            ..Default::default()
        }
    }
    fn host(group: &str, route: &str) -> Host {
        Host { address: "10.0.0.1".into(), group: group.into(), route: route.into(), ..Default::default() }
    }

    #[test]
    fn hosts_inherit_the_nearest_group_route_and_can_opt_out() {
        let routes = vec![route("lon", Kind::Ssh, ""), route("lab", Kind::Socks5, "")];
        let mut groups = Groups::new();
        groups.insert("London".into(), GroupSettings { route: "lon".into() });
        groups.insert("London / Lab".into(), GroupSettings { route: "lab".into() });
        groups.insert("London / Lab / Bench".into(), GroupSettings { route: DIRECT.into() });

        let r = resolve(&host("London / Compute", ""), &groups, &routes).unwrap();
        assert_eq!(r.chain[0].name, "lon");
        assert_eq!(r.source, Source::Group("London".into()));
        assert_eq!(r.summary(), "lon, from London");

        let r = resolve(&host("London / Lab / Rack 2", ""), &groups, &routes).unwrap();
        assert_eq!(r.chain[0].name, "lab");

        let r = resolve(&host("London / Lab / Bench", ""), &groups, &routes).unwrap();
        assert!(r.chain.is_empty(), "a group's `direct` stops inheritance");

        let r = resolve(&host("London / Compute", DIRECT), &groups, &routes).unwrap();
        assert!(r.chain.is_empty());
        assert_eq!(r.source, Source::Host);

        assert_eq!(resolve(&host("Paris", ""), &groups, &routes).unwrap().source, Source::Default);

        // The legacy datacenter field folds into the path, as the sidebar shows it.
        let h = Host { group: "Compute".into(), datacenter: "London".into(), ..Default::default() };
        assert_eq!(resolve(&h, &groups, &routes).unwrap().chain[0].name, "lon");

        assert_eq!(inherited(&host("London / Compute", DIRECT), &groups, &routes).unwrap().chain[0].name, "lon");
        assert_eq!(group_inherited("London / Lab", &groups, &routes).unwrap().summary(), "lon, from London");
    }

    #[test]
    fn chains_run_outermost_first_and_refuse_loops_depth_and_missing_names() {
        let routes = vec![route("a", Kind::Ssh, ""), route("b", Kind::Socks5, "a"), route("c", Kind::Ssh, "b")];
        let names: Vec<_> = chain("c", &routes).unwrap().into_iter().map(|r| r.name).collect();
        assert_eq!(names, ["a", "b", "c"]);

        let looped = vec![route("x", Kind::Ssh, "y"), route("y", Kind::Ssh, "x")];
        assert!(chain("x", &looped).unwrap_err().contains("loops"));

        let deep: Vec<_> = (0..6)
            .map(|i| route(&format!("r{i}"), Kind::Ssh, &if i == 0 { String::new() } else { format!("r{}", i - 1) }))
            .collect();
        assert!(chain("r5", &deep).unwrap_err().contains("more than"));
        assert!(chain("missing", &routes).unwrap_err().contains("no route named"));

        // A host that names a missing route fails; it never quietly goes direct.
        assert!(resolve(&host("", "gone"), &Groups::new(), &routes).is_err());
    }

    #[test]
    fn validation_rename_and_users() {
        let mut routes = vec![route("lon", Kind::Ssh, ""), route("inner", Kind::Socks5, "lon")];
        let mut dup = route("LON", Kind::Ssh, "");
        assert!(validate(&dup, &routes).unwrap_err().contains("already"));
        dup.name = "Direct".into();
        assert!(validate(&dup, &routes).unwrap_err().contains("reserved"));
        dup.name = "inherit".into();
        assert!(validate(&dup, &routes).unwrap_err().contains("reserved"));
        for bad in ["-x", "two words", "tab\there"] {
            dup.name = bad.into();
            assert!(validate(&dup, &routes).unwrap_err().contains("cannot be a route's name"), "{bad}");
        }
        let mut no_user = route("new", Kind::Ssh, "");
        no_user.user.clear();
        assert!(validate(&no_user, &routes).is_err());
        let mut key = route("new", Kind::Ssh, "");
        key.auth = Auth::Key;
        assert!(validate(&key, &routes).unwrap_err().contains("key file"));
        let mut anonymous = route("new", Kind::Socks5, "");
        (anonymous.user, anonymous.secret) = (String::new(), "pw".into());
        assert!(validate(&anonymous, &routes).unwrap_err().contains("needs a user"));
        let mut bad_host = route("new", Kind::Socks5, "");
        bad_host.host = "https://proxy".into();
        assert!(validate(&bad_host, &routes).is_err());
        assert!(validate(&route("ok", Kind::Socks5, "inner"), &routes).is_ok());

        let mut hosts = vec![host("", "lon")];
        let mut groups = Groups::new();
        groups.insert("London".into(), GroupSettings { route: "lon".into() });
        assert_eq!(users("lon", &hosts, &groups, &routes).len(), 3, "the host, the group and inner's via");
        rename("lon", "london-jump", &mut hosts, &mut groups, &mut routes);
        assert_eq!(hosts[0].route, "london-jump");
        assert_eq!(groups["London"].route, "london-jump");
        assert_eq!(routes[0].name, "london-jump");
        assert_eq!(routes[1].via, "london-jump");
    }

    #[test]
    fn a_groups_json_that_does_not_parse_fails_every_host_that_would_read_it() {
        let routes = vec![route("lon", Kind::Ssh, "")];
        let broken: LoadedGroups = parse_groups(br#"{"London": {"route": "lon"},}"#).map_err(|e| format!("groups.json: {e}"));
        assert!(broken.is_err(), "a trailing comma does not parse");
        let inherits = host("London", "");
        let e = resolve_loaded(&inherits, &broken, &routes).unwrap_err();
        assert!(e.starts_with("groups.json: "), "{e}");
        // Hosts that name their own route, or opt out, never read the groups.
        assert_eq!(resolve_loaded(&host("London", "lon"), &broken, &routes).unwrap().chain[0].name, "lon");
        assert!(resolve_loaded(&host("London", DIRECT), &broken, &routes).unwrap().chain.is_empty());

        let t = table(&[inherits], &broken, &routes);
        assert!(t.chain_for("10.0.0.1").unwrap_err().starts_with("groups.json: "), "never direct");
    }

    #[test]
    fn one_address_listed_twice_with_different_routes_gets_neither() {
        let routes = vec![route("lon", Kind::Ssh, "")];
        let spelled = |address: &str, route: &str| Host { address: address.into(), route: route.into(), ..Default::default() };
        let t = table(&[spelled("fd00::5", "lon"), spelled("FD00:0::5", "")], &Ok(Groups::new()), &routes);
        let e = t.chain_for("fd00::5").unwrap_err();
        assert_eq!(e, "fd00::5 is listed twice with different routes");
        // Listed twice the same way is only untidy.
        let t = table(&[spelled("fd00::5", "lon"), spelled("FD00:0::5", "lon")], &Ok(Groups::new()), &routes);
        assert_eq!(t.chain_for("fd00::5").unwrap()[0].name, "lon");
        // A third spelling that agrees with the first does not mend it.
        let three = [spelled("fd00::5", "lon"), spelled("FD00:0::5", ""), spelled("fd00:0:0::5", "lon")];
        assert!(table(&three, &Ok(Groups::new()), &routes).chain_for("fd00::5").is_err());
    }

    #[test]
    fn a_routes_json_that_does_not_parse_is_named_by_every_host_that_needs_it() {
        let broken: LoadedRoutes = Err("routes.json: trailing comma".into());
        let at = |address: &str, group: &str, route: &str| Host {
            address: address.into(),
            group: group.into(),
            route: route.into(),
            ..Default::default()
        };
        let hosts = [at("10.20.1.1", "", "lon"), at("10.20.1.2", "London", ""), at("10.20.1.3", "London", DIRECT)];
        let mut groups = Groups::new();
        groups.insert("London".into(), GroupSettings { route: "lon".into() });
        let t = table_loaded(&hosts, &Ok(groups), &broken);
        assert_eq!(t.chain_for("10.20.1.1").unwrap_err(), "routes.json: trailing comma", "not \"no route named lon\"");
        assert_eq!(t.chain_for("10.20.1.2").unwrap_err(), "routes.json: trailing comma");
        assert!(t.chain_for("10.20.1.3").unwrap().is_empty(), "a host that goes direct still does");
        // With groups.json broken too, a host that inherits cannot tell
        // whether it needs a route: that file's error stands.
        let t = table_loaded(&hosts, &Err("groups.json: x".into()), &broken);
        assert_eq!(t.chain_for("10.20.1.2").unwrap_err(), "groups.json: x");

        assert!(route_chain_loaded(DIRECT, &broken).unwrap().is_empty());
        assert_eq!(route_chain_loaded("lon", &broken).unwrap_err(), "routes.json: trailing comma");
        let fine: LoadedRoutes = Ok(vec![route("lon", Kind::Ssh, "")]);
        assert_eq!(table_loaded(&hosts, &Ok(Groups::new()), &fine).chain_for("10.20.1.1").unwrap()[0].name, "lon");
    }

    #[test]
    fn a_datacenter_written_with_a_slash_finds_its_group() {
        let g = parse_groups(br#"{"DC1/Row4": {"route": "lab"}}"#).unwrap();
        let routes = vec![route("lab", Kind::Socks5, "")];
        let h = Host { group: "Bench".into(), datacenter: "DC1/Row4".into(), ..Default::default() };
        let r = resolve(&h, &g, &routes).unwrap();
        assert_eq!(r.source, Source::Group("DC1 / Row4".into()), "never direct");
    }

    #[test]
    fn group_keys_are_read_as_the_sidebar_prints_paths() {
        let g = parse_groups(br#"{"London/Lab ": {"route": "lab"}}"#).unwrap();
        assert_eq!(g.keys().collect::<Vec<_>>(), ["London / Lab"]);
        let routes = vec![route("lab", Kind::Socks5, "")];
        let h = Host { group: "Lab".into(), datacenter: "London".into(), ..Default::default() };
        assert_eq!(resolve(&h, &g, &routes).unwrap().source, Source::Group("London / Lab".into()));
        let e = parse_groups(br#"{"London / Lab": {}, "London/Lab": {}}"#).unwrap_err();
        assert!(e.contains("again"), "{e}");
    }

    #[test]
    fn old_files_load_and_new_ones_round_trip() {
        let h: Host = serde_json::from_str(r#"{"name":"a","address":"10.0.0.1"}"#).unwrap();
        assert!(h.route.is_empty());
        let r: Route =
            serde_json::from_str(r#"{"name":"j","kind":"ssh","host":"jump","port":22,"user":"ops"}"#).unwrap();
        assert_eq!((r.kind, r.auth), (Kind::Ssh, Auth::Agent));
        let text = serde_json::to_string(&vec![r.clone()]).unwrap();
        assert_eq!(serde_json::from_str::<Vec<Route>>(&text).unwrap(), vec![r]);
        let mut g = Groups::new();
        g.insert("London".into(), GroupSettings { route: "j".into() });
        assert_eq!(serde_json::from_str::<Groups>(&serde_json::to_string(&g).unwrap()).unwrap(), g);
    }
}
