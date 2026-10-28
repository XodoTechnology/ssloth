//! Saved BMC inventory: load/save a small JSON store, seeded from the legacy
//! ~/.config/smc-ikvm/hosts.ini so existing credentials keep working.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Host {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub note: String,
    /// The BMC family last detected for this host, as `Family::key()`. Cached so
    /// a restart can label and icon the list before any probe has answered; the
    /// probe still runs and overwrites it if the machine has been swapped out.
    #[serde(default)]
    pub family: String,
    /// The vendor last detected, as `Vendor::key()` — cached for the same
    /// reason as `family`, and empty when the family implies it.
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub datacenter: String,
    #[serde(default)]
    pub rack: String,
    #[serde(default)]
    pub tags: String,
    /// The route this host is reached through: empty inherits its group's,
    /// `direct` opts out, anything else names a route in routes.json.
    #[serde(default)]
    pub route: String,
}

impl Host {
    pub fn label(&self) -> &str {
        if self.name.trim().is_empty() { &self.address } else { &self.name }
    }
}

/// Where the inventory and the legacy ini live.
///
/// `~/.config/smc-ikvm` on Unix — the directory name predates the rename to
/// bmc-kvm and is left alone, because changing it would strand every existing
/// host list. Windows has no `HOME` and no `~/.config` convention, so it gets
/// `%APPDATA%\bmc-kvm`, falling back to `%USERPROFILE%` if APPDATA is somehow
/// unset.
pub fn config_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("BMCKVM_CONFIG_DIR").filter(|p| !p.is_empty()) {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                return PathBuf::from(appdata).join("bmc-kvm");
            }
        }
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        return PathBuf::from(home).join("AppData").join("Roaming").join("bmc-kvm");
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home).join(".config").join("smc-ikvm")
    }
}

/// The host's place in the group tree, as the sidebar shows it: the group
/// path with the legacy `datacenter` folded in at the root, or "Ungrouped".
pub fn location(host: &Host) -> String {
    // Both through group_path, the datacenter too: a `DC1/Row4` must read
    // as the `DC1 / Row4` a groups.json key is normalised to, or its hosts
    // would miss their group's route and go direct.
    let group = group_path(&host.group);
    let dc = group_path(&host.datacenter);
    if group.is_empty() {
        return if dc.is_empty() {
            "Ungrouped".into()
        } else {
            dc
        };
    }
    // A group path that already names the datacenter is not prefixed again.
    if dc.is_empty() || format!(" / {group} / ").contains(&format!(" / {dc} / ")) {
        group
    } else {
        format!("{dc} / {group}")
    }
}

/// A group path as `location` prints it, however it was typed: `London/Lab`
/// and ` London / Lab /` are both `London / Lab`. groups.json keys and
/// `route group`'s path go through it too, so a group's settings find its
/// hosts however either was spaced.
pub fn group_path(raw: &str) -> String {
    raw.split('/').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" / ")
}

pub fn store_path() -> PathBuf { config_dir().join("hosts.json") }
fn ini_path() -> PathBuf { config_dir().join("hosts.ini") }

/// Credentials from the legacy ini: (per-host map, default user/pass).
pub fn ini_credentials() -> (Vec<(String, String, String)>, Option<(String, String)>) {
    let mut per_host = Vec::new();
    let mut default = None;
    let Ok(txt) = std::fs::read_to_string(ini_path()) else { return (per_host, default) };
    let mut section = String::new();
    let (mut u, mut p) = (String::new(), String::new());
    let flush = |section: &str, u: &mut String, p: &mut String,
                     per_host: &mut Vec<(String, String, String)>,
                     default: &mut Option<(String, String)>| {
        if section.is_empty() { return; }
        if u.is_empty() && p.is_empty() { return; }
        if section.eq_ignore_ascii_case("DEFAULT") {
            *default = Some((u.clone(), p.clone()));
        } else {
            per_host.push((section.to_string(), u.clone(), p.clone()));
        }
        u.clear(); p.clear();
    };
    for line in txt.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') { continue; }
        if l.starts_with('[') && l.ends_with(']') {
            flush(&section, &mut u, &mut p, &mut per_host, &mut default);
            section = l[1..l.len() - 1].to_string();
        } else if let Some((k, v)) = l.split_once('=') {
            match k.trim() {
                "user" => u = v.trim().to_string(),
                "password" => p = v.trim().to_string(),
                _ => {}
            }
        }
    }
    flush(&section, &mut u, &mut p, &mut per_host, &mut default);
    (per_host, default)
}

pub fn load() -> Vec<Host> {
    try_load().unwrap_or_else(|_| from_ini())
}

/// Like `load`, but a hosts.json that exists and does not parse is an error,
/// not the ini's hosts: those carry no routes, so a command that took them
/// would reach every routed host directly.
pub fn try_load() -> Result<Vec<Host>, String> {
    match std::fs::read_to_string(store_path()) {
        Ok(txt) => serde_json::from_str(&txt).map_err(|e| format!("{}: {e}", store_path().display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(from_ini()),
        Err(e) => Err(format!("{}: {e}", store_path().display())),
    }
}

/// First run: seed from the ini so saved BMCs show up immediately.
fn from_ini() -> Vec<Host> {
    let (per_host, _default) = ini_credentials();
    per_host.into_iter()
        .map(|(addr, user, password)| Host {
            name: String::new(), address: addr, group: String::new(), user, password,
            note: String::new(), family: String::new(), ..Default::default()
        })
        .collect()
}

pub fn save(hosts: &[Host]) -> std::io::Result<()> {
    write_inventory(&store_path(), hosts)
}

/// Tests that write hosts.json take turns: the config directory is shared
/// by the whole test process.
#[cfg(any(test, feature = "testing"))]
pub fn file_turn() -> std::sync::MutexGuard<'static, ()> {
    static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read hosts.json, change it and write it back, as one step under the
/// inventory lock, and return what was written. The GUI holds its hosts for
/// the whole run while `bmc-kvm route host` and `route rename` change them
/// on disk, so it changes the file as it is now rather than saving its own
/// copy over theirs. A hosts.json that does not parse is reported, never
/// replaced: it may name routes that a rewrite would lose.
pub fn edit_hosts<T>(change: impl FnOnce(&mut Vec<Host>) -> Result<T, String>) -> Result<(T, Vec<Host>), String> {
    locked(|| {
        let mut hosts = try_load()?;
        let out = change(&mut hosts)?;
        save(&hosts).map_err(|e| format!("{}: {e}", store_path().display()))?;
        Ok((out, hosts))
    })?
}

/// Give `on_disk` the fields in which `after` differs from `before` and
/// leave the rest as the file has them: a field this edit did not touch,
/// such as the route, may have been changed by another bmc-kvm meanwhile.
pub fn merge_changes(on_disk: &mut Host, before: &Host, after: &Host) {
    let as_map = |h: &Host| match serde_json::to_value(h) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => unreachable!("a Host is a JSON object"),
    };
    let (before, after, mut merged) = (as_map(before), as_map(after), as_map(on_disk));
    for (field, value) in after {
        if before.get(&field) != Some(&value) {
            merged.insert(field, value);
        }
    }
    *on_disk = serde_json::from_value(serde_json::Value::Object(merged)).expect("fields of a Host make a Host");
}

thread_local! {
    /// Whether this thread holds the inventory lock, so that a step taken
    /// under it can call another that takes it.
    static HOLDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f`, a read-change-write of hosts.json, groups.json or routes.json,
/// as the only one: in this process, and in any other bmc-kvm on the same
/// config directory. Each writer replaces the whole file, so two that read
/// the same version would each save without the other's change: twelve
/// `route add`s at once used to leave two routes. The lock is advisory and
/// on a file of its own, which is never removed. Taking it again on a thread
/// that holds it runs `f` at once.
pub fn locked<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    if HOLDING.with(std::cell::Cell::get) {
        return Ok(f());
    }
    // flock and LockFileEx already shut out other handles in this process;
    // the mutex says so without leaning on that.
    static IN_PROCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _turn = IN_PROCESS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = config_dir().join(".inventory.lock");
    let failed = |e: std::io::Error| format!("{}: {e}", path.display());
    std::fs::create_dir_all(config_dir()).map_err(failed)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(failed)?;
    match file.lock() {
        Ok(()) => {}
        // A filesystem without locks: this process is still kept in turn.
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
        Err(e) => return Err(failed(e)),
    }
    struct Held;
    impl Drop for Held {
        fn drop(&mut self) {
            HOLDING.with(|h| h.set(false));
        }
    }
    HOLDING.with(|h| h.set(true));
    let held = Held;
    let out = f();
    drop(held);
    // Closing the file releases the lock.
    drop(file);
    Ok(out)
}

static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Bumped by every inventory write, so the GUI can tell that the route table
/// it built from hosts, groups and routes has gone stale.
pub fn generation() -> u64 {
    GENERATION.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn write_inventory<T: Serialize + ?Sized>(path: &std::path::Path, hosts: &T) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "inventory path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_vec_pretty(hosts)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    // The name must be unique to this write, not merely to this moment:
    // save() and WorkspaceSettings::save() run outside the inventory lock,
    // and on Windows two threads routinely read the same SystemTime. A
    // shared name failed create_new in one writer (os error 80), whose
    // cleanup then deleted the other's half-written file from under it.
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let temp = dir.join(format!(".hosts-{}-{sequence}-{nonce}.tmp", std::process::id()));
    let mut created = false;
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // Create the replacement with restrictive permissions before any
        // credentials are written; a failed save leaves the old inventory intact.
        let mut file = options.open(&temp)?;
        created = true;
        file.write_all(&json)?;
        file.sync_all()?;
        drop(file);
        // MoveFileExW with MOVEFILE_REPLACE_EXISTING on Windows, so this
        // replaces the old file there as rename(2) does on Unix.
        std::fs::rename(&temp, path)
    })();
    // Only a file this write created is ours to remove.
    if result.is_err() && created { let _ = std::fs::remove_file(&temp); }
    else { GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    result
}

/// Effective credentials for a host: its own, else the ini [DEFAULT].
pub fn credentials_for(h: &Host) -> (String, String) {
    if !h.user.is_empty() && !h.password.is_empty() {
        return (h.user.clone(), h.password.clone());
    }
    let (per_host, default) = ini_credentials();
    if let Some((_, u, p)) = per_host.into_iter().find(|(a, _, _)| a.eq_ignore_ascii_case(&h.address)) {
        return (u, p);
    }
    default.unwrap_or_default()
}


#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceSettings {
    pub allow_untrusted_certs: bool,
    /// The version whose "What's new" page was last opened. The sidebar marks
    /// the link until it is the running one, so an upgrade gets noticed.
    pub seen_changelog: String,
}
impl Default for WorkspaceSettings {
    fn default() -> Self { Self { allow_untrusted_certs: true, seen_changelog: String::new() } }
}
impl WorkspaceSettings {
    pub fn load() -> Self {
        std::fs::read(config_dir().join("workspace-settings.json")).ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        write_inventory(&config_dir().join("workspace-settings.json"), self)
    }
}


#[cfg(test)]
mod settings_tests {
    use super::*;
    #[test]
    fn untrusted_certificates_default_on_and_explicit_false_persists() {
        assert!(WorkspaceSettings::default().allow_untrusted_certs);
        assert!(serde_json::from_str::<WorkspaceSettings>("{}").unwrap().allow_untrusted_certs);
        let path = std::env::temp_dir().join(format!("bmc-kvm-settings-test-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        write_inventory(&path,&WorkspaceSettings { allow_untrusted_certs: false, ..Default::default() }).unwrap();
        let settings: WorkspaceSettings = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(!settings.allow_untrusted_certs);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,0o600);
        }
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    #[test]
    fn every_location_is_already_a_normalised_group_path() {
        let cases = [
            ("", ""),
            ("Lab", ""),
            ("", "DC1/Row4"),
            ("Lab", "DC1/Row4"),
            (" DC1 / Row4 /Lab", "DC1/Row4"),
            ("a//b/", " London "),
            ("London/Compute", "London"),
        ];
        for (group, datacenter) in cases {
            let h = Host { group: group.into(), datacenter: datacenter.into(), ..Default::default() };
            let l = location(&h);
            assert_eq!(l, group_path(&l), "{group:?} in {datacenter:?}");
        }
        let at = |group: &str| location(&Host { group: group.into(), datacenter: "DC1/Row4".into(), ..Default::default() });
        assert_eq!(at("Lab"), "DC1 / Row4 / Lab");
        assert_eq!(at(""), "DC1 / Row4");
        assert_eq!(at("DC1/Row4/Lab"), "DC1 / Row4 / Lab", "a path that names its datacenter is not prefixed again");
    }

    #[test]
    fn a_merge_keeps_the_fields_the_edit_did_not_touch() {
        let before = Host { address: "10.20.1.11".into(), name: "old".into(), ..Default::default() };
        let after = Host { name: "new".into(), tags: "lab".into(), ..before.clone() };
        // Meanwhile `route host` gave it a route, and another edit a note.
        let mut on_disk = Host { route: "jump".into(), note: "kept".into(), ..before.clone() };
        merge_changes(&mut on_disk, &before, &after);
        assert_eq!((on_disk.name.as_str(), on_disk.tags.as_str()), ("new", "lab"));
        assert_eq!((on_disk.route.as_str(), on_disk.note.as_str()), ("jump", "kept"));
    }

    #[test]
    fn hosts_are_edited_as_the_file_has_them_and_never_over_one_that_does_not_parse() {
        crate::net::ssh::testing::isolate_config();
        let _turn = file_turn();
        let at = |a: &str| Host { address: a.into(), ..Default::default() };
        save(&[at("10.20.1.11")]).unwrap();
        // Another bmc-kvm routes the host after this one read the file.
        let mut routed = at("10.20.1.11");
        routed.route = "jump".into();
        save(&[routed]).unwrap();
        let (n, saved) = edit_hosts(|hosts| {
            hosts.push(at("10.20.1.12"));
            Ok(hosts.len())
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(saved[0].route, "jump", "the other's change stands");
        assert_eq!(try_load().unwrap().len(), 2);

        std::fs::write(store_path(), "{ not json").unwrap();
        let e = edit_hosts(|hosts| {
            hosts.push(at("10.20.1.13"));
            Ok(())
        })
        .unwrap_err();
        assert!(e.contains("hosts.json"), "{e}");
        assert_eq!(std::fs::read_to_string(store_path()).unwrap(), "{ not json", "left for the user to mend");
        std::fs::remove_file(store_path()).unwrap();
    }

    #[test]
    fn the_inventory_lock_shuts_out_every_other_handle() {
        crate::net::ssh::testing::isolate_config();
        let (taken, wait_taken) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            locked(|| {
                taken.send(()).unwrap();
                wait_release.recv().unwrap();
            })
        });
        wait_taken.recv().unwrap();
        // A handle of its own, as another process would have.
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(config_dir().join(".inventory.lock"))
            .unwrap();
        assert!(matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)), "held elsewhere");
        release.send(()).unwrap();
        holder.join().unwrap().unwrap();
        // Other tests in this process take it too: wait for a free moment.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while let Err(std::fs::TryLockError::WouldBlock) = other.try_lock() {
            assert!(std::time::Instant::now() < deadline, "never let go");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn writers_at_once_each_keep_their_change() {
        crate::net::ssh::testing::isolate_config();
        let writers: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    crate::routes::edit_routes(|routes| {
                        routes.push(crate::routes::Route { name: format!("lock-{i}"), ..Default::default() });
                        Ok(())
                    })
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap().unwrap();
        }
        let saved = crate::routes::try_load_routes().unwrap();
        for i in 0..8 {
            assert!(saved.iter().any(|r| r.name == format!("lock-{i}")), "lock-{i} kept");
        }
    }
}
