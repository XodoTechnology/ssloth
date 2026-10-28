//! Which user and password to log in to a BMC with, for the CLI and the GUI
//! alike. They once each had their own lookup, which matched hosts
//! differently and read the legacy ini with a second parser, so the same
//! host could log in as one user from the GUI and another from the shell.

use crate::hosts;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredsError {
    /// hosts.json exists and cannot be read. Its credentials may be the
    /// ones meant, so it is reported rather than read as empty.
    Inventory(String),
    /// Nothing anywhere names a user and a password for this host.
    Missing { host: String, config_dir: String },
}

impl fmt::Display for CredsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredsError::Inventory(e) => write!(f, "cannot read the host inventory: {e}"),
            CredsError::Missing { host, config_dir } => write!(
                f,
                "no credentials for {host}: pass --user and --password, set IKVM_USER and \
                 IKVM_PASSWORD, or save them in {config_dir}"
            ),
        }
    }
}

impl std::error::Error for CredsError {}

/// The credentials for `addr`, each field from the first place that has it:
/// `user`/`pass` as given (the command-line flags), then the host's own in
/// hosts.json, then `IKVM_USER`/`IKVM_PASSWORD`, then the legacy hosts.ini,
/// its section for the host before its `[DEFAULT]`.
///
/// Hosts are matched as the route table matches them (`net::same_address`),
/// so `10.0.0.5`, `[10.0.0.5]` and a hostname in another case all find the
/// entry the GUI would.
pub fn resolve(addr: &str, user: Option<String>, pass: Option<String>) -> Result<(String, String), CredsError> {
    resolve_with(addr, user, pass, |k| std::env::var(k).ok())
}

fn resolve_with(
    addr: &str,
    user: Option<String>,
    pass: Option<String>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<(String, String), CredsError> {
    let mut found = Found::default();
    if found.fill(user, pass) {
        return Ok(found.pair());
    }
    let inventory = hosts::try_load().map_err(CredsError::Inventory)?;
    // A host's own credentials are a pair: half of one is not a login.
    let own = inventory.into_iter()
        .find(|h| crate::net::same_address(&h.address, addr))
        .filter(|h| !h.user.is_empty() && !h.password.is_empty());
    if let Some(h) = own {
        if found.fill(Some(h.user), Some(h.password)) { return Ok(found.pair()); }
    }
    if found.fill(env("IKVM_USER"), env("IKVM_PASSWORD")) {
        return Ok(found.pair());
    }
    let (per_host, default) = hosts::ini_credentials();
    let section = per_host.into_iter().find(|(a, _, _)| crate::net::same_address(a, addr));
    for (u, p) in section.map(|(_, u, p)| (u, p)).into_iter().chain(default) {
        if found.fill(Some(u), Some(p)) { return Ok(found.pair()); }
    }
    Err(CredsError::Missing {
        host: addr.to_string(),
        config_dir: hosts::config_dir().display().to_string(),
    })
}

/// Each field as the first source that had it; an empty one is not had.
#[derive(Default)]
struct Found { user: Option<String>, pass: Option<String> }
impl Found {
    fn fill(&mut self, user: Option<String>, pass: Option<String>) -> bool {
        let given = |v: Option<String>| v.filter(|s| !s.is_empty());
        if self.user.is_none() { self.user = given(user); }
        if self.pass.is_none() { self.pass = given(pass); }
        self.user.is_some() && self.pass.is_some()
    }
    fn pair(self) -> (String, String) {
        (self.user.unwrap_or_default(), self.pass.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::{file_turn, Host};

    fn some(s: &str) -> Option<String> { Some(s.into()) }
    fn no_env(_: &str) -> Option<String> { None }
    fn env(k: &str) -> Option<String> {
        match k {
            "IKVM_USER" => some("envuser"),
            "IKVM_PASSWORD" => some("envpass"),
            _ => None,
        }
    }
    fn pair(u: &str, p: &str) -> Result<(String, String), CredsError> { Ok((u.into(), p.into())) }

    /// A config directory holding exactly these files; the guard keeps other
    /// tests off it until the test ends, and the files go with it.
    struct Config { _turn: std::sync::MutexGuard<'static, ()> }
    impl Config {
        fn with(hosts_json: Option<&[Host]>, ini: Option<&str>) -> Self {
            crate::net::ssh::testing::isolate_config();
            let turn = file_turn();
            let dir = hosts::config_dir();
            let _ = std::fs::remove_file(dir.join("hosts.json"));
            let _ = std::fs::remove_file(dir.join("hosts.ini"));
            if let Some(h) = hosts_json { hosts::save(h).unwrap(); }
            if let Some(ini) = ini { std::fs::write(dir.join("hosts.ini"), ini).unwrap(); }
            Config { _turn: turn }
        }
    }
    impl Drop for Config {
        fn drop(&mut self) {
            let dir = hosts::config_dir();
            let _ = std::fs::remove_file(dir.join("hosts.json"));
            let _ = std::fs::remove_file(dir.join("hosts.ini"));
        }
    }
    fn host(addr: &str, u: &str, p: &str) -> Host {
        Host { address: addr.into(), user: u.into(), password: p.into(), ..Default::default() }
    }
    const INI: &str = "[DEFAULT]\nuser = iniuser\npassword = inipass\n\n[192.0.2.9]\nuser = hostini\npassword = hostinipass\n";

    #[test]
    fn flags_come_first() {
        let _c = Config::with(Some(&[host("192.0.2.1", "saved", "savedpass")]), Some(INI));
        assert_eq!(resolve_with("192.0.2.1", some("flag"), some("flagpass"), env), pair("flag", "flagpass"));
        // One flag fills its own field and the rest comes from further down.
        assert_eq!(resolve_with("192.0.2.1", some("flag"), None, env), pair("flag", "savedpass"));
    }

    #[test]
    fn the_inventory_comes_before_the_environment() {
        let _c = Config::with(Some(&[host("192.0.2.1", "saved", "savedpass")]), Some(INI));
        assert_eq!(resolve_with("192.0.2.1", None, None, env), pair("saved", "savedpass"));
        drop(_c);
        // A host saved without credentials falls through.
        let _c = Config::with(Some(&[host("192.0.2.1", "", "")]), Some(INI));
        assert_eq!(resolve_with("192.0.2.1", None, None, env), pair("envuser", "envpass"));
    }

    #[test]
    fn the_environment_comes_before_the_ini() {
        let _c = Config::with(Some(&[]), Some(INI));
        assert_eq!(resolve_with("192.0.2.9", None, None, env), pair("envuser", "envpass"));
    }

    #[test]
    fn the_ini_section_comes_before_its_default() {
        let _c = Config::with(Some(&[]), Some(INI));
        assert_eq!(resolve_with("192.0.2.9", None, None, no_env), pair("hostini", "hostinipass"));
        assert_eq!(resolve_with("192.0.2.10", None, None, no_env), pair("iniuser", "inipass"));
    }

    #[test]
    fn hosts_match_by_canonical_address() {
        let _c = Config::with(Some(&[host("[FD00:0:0::5]", "v6", "v6pass"), host("BMC-A.invalid", "named", "namedpass")]), None);
        assert_eq!(resolve_with("fd00::5", None, None, no_env), pair("v6", "v6pass"));
        assert_eq!(resolve_with("bmc-a.invalid", None, None, no_env), pair("named", "namedpass"));
    }

    #[test]
    fn nothing_found_names_the_config_dir_and_a_broken_inventory_is_an_error() {
        let _c = Config::with(Some(&[]), None);
        let e = resolve_with("192.0.2.1", None, None, no_env).unwrap_err();
        assert!(matches!(e, CredsError::Missing { .. }));
        assert!(e.to_string().contains(&hosts::config_dir().display().to_string()), "{e}");
        std::fs::write(hosts::store_path(), "{ not json").unwrap();
        assert!(matches!(resolve_with("192.0.2.1", None, None, env), Err(CredsError::Inventory(_))));
        // Flags alone need no inventory at all.
        assert_eq!(resolve_with("192.0.2.1", some("u"), some("p"), no_env), pair("u", "p"));
    }
}
