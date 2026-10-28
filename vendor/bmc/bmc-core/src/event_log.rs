//! Read-only IPMI SEL and standards-based Redfish log discovery.
use crate::families::Family;
use serde_json::Value;
use std::{
    collections::HashSet,
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub id: String,
    pub created: String,
    pub source: String,
    pub severity: String,
    pub message: String,
}
#[derive(Clone, Debug, Default)]
pub struct Log {
    pub source: &'static str,
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
}

// Drain both pipes while polling so a large SEL cannot deadlock the subprocess.
fn run(mut command: Command, input: Option<String>, timeout: Duration) -> Result<String, String> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| {
        format!("Cannot start log reader: {e}. Install curl to read Redfish telemetry.")
    })?;
    if let Some(input) = input {
        if let Err(e) = child.stdin.take().unwrap().write_all(input.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Cannot configure log reader: {e}"));
        }
    }
    fn drain(mut stream: impl Read) -> std::io::Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut buf = [0; 8192];
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if data.len() < 16 * 1024 * 1024 {
                data.extend_from_slice(&buf[..n]);
            }
        }
        if data.len() >= 16 * 1024 * 1024 {
            return Err(std::io::Error::other("Log response exceeds 16 MiB"));
        }
        Ok(data)
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || drain(stdout));
    let err = std::thread::spawn(move || drain(stderr));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(50)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(match result {
                    Err(e) => e.to_string(),
                    _ => "Log request timed out".into(),
                });
            }
        }
    };
    let out = out
        .join()
        .map_err(|_| "Log reader failed")?
        .map_err(|e| e.to_string())?;
    let err = err
        .join()
        .map_err(|_| "Log reader failed")?
        .map_err(|e| e.to_string())?;
    let status = status?;
    if !status.success() {
        let message = String::from_utf8_lossy(&err).trim().to_owned();
        return Err(if message.is_empty() {
            format!("Controller reader exited with {status}")
        } else {
            message
        });
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}

/// The System Event Log over IPMI, read by the native client (`crate::ipmi`),
/// with sensor names from the SDR so entries read like `ipmitool sel elist`.
pub fn ipmi(host: &str, user: &str, password: &str) -> Result<Log, String> {
    let mut s = crate::ipmi::Session::open(host, user, password).map_err(|e| e.to_string())?;
    let mut warnings = Vec::new();
    // Names are a nicety: without the SDR the log still reads, by number.
    let sdr = crate::ipmi_records::read_sdr(&mut s).unwrap_or_else(|e| {
        warnings.push(format!("Sensor names unavailable: {e}"));
        Vec::new()
    });
    let sel = crate::ipmi_records::read_sel(&mut s, &sdr).map_err(|e| e.to_string())?;
    let entries = sel
        .into_iter()
        .rev() // newest first, as the Redfish readers list them
        .map(|e| Entry {
            id: format!("{:#06x}", e.id),
            created: e.time,
            source: e.sensor,
            severity: e.direction,
            message: e.event,
        })
        .collect();
    Ok(Log { source: "IPMI SEL", entries, warnings })
}

pub(crate) fn safe_path(path: &str) -> Result<&str, String> {
    if !path.starts_with("/redfish/v1/")
        || path.contains(['\r', '\n', '\\', '#'])
        || path.split('/').any(|p| p == "..")
    {
        return Err("BMC returned an invalid Redfish resource link".into());
    }
    Ok(path)
}
fn quoted(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
/// curl's arguments and stdin config for one Redfish GET. A routed host goes
/// through the loopback front end (`proxy`), which reaches the BMC over its
/// route; a direct one keeps `--noproxy *`, so an environment proxy never
/// sees BMC credentials.
fn curl_request(
    host: &str,
    path: &str,
    user: &str,
    password: &str,
    insecure: bool,
    proxy: Option<(&str, &str)>,
) -> (Vec<String>, String) {
    let mut args: Vec<String> = ["-q", "--silent", "--show-error", "--fail"].map(String::from).to_vec();
    if proxy.is_none() {
        args.extend(["--noproxy", "*"].map(String::from));
    }
    // A first request through a jump host may have to open the tunnel.
    let (connect_timeout, max_time) = if proxy.is_some() { ("20", "30") } else { ("4", "12") };
    args.extend(
        ["--connect-timeout", connect_timeout, "--max-time", max_time, "--max-filesize", "16777216", "--proto", "=https", "--config", "-"]
            .map(String::from),
    );
    if insecure {
        args.push("--insecure".into());
    }
    let mut config = format!("url = \"https://{host}{}\"\nuser = \"{}:{}\"\n", quoted(path), quoted(user), quoted(password));
    if let Some((url, cred)) = proxy {
        // An empty list also overrides NO_PROXY: curl would otherwise apply it
        // to this proxy and send the credentials straight to the BMC.
        config.push_str(&format!("noproxy = \"\"\nproxy = \"{}\"\nproxy-user = \"{}\"\n", quoted(url), quoted(cred)));
    }
    (args, config)
}
/// curl reports every SOCKS refusal as the same generic failure; the front
/// end knows which hop or step actually failed.
fn with_route_cause(curl_error: String, cause: Option<String>) -> String {
    match cause {
        Some(why) => format!("{curl_error} ({why})"),
        None => curl_error,
    }
}
struct Client<'a> {
    host: &'a str,
    user: &'a str,
    password: &'a str,
    insecure: bool,
    started: Instant,
}
impl Client<'_> {
    fn get(&self, path: &str) -> Result<Value, String> {
        if self.started.elapsed() > Duration::from_secs(90) {
            return Err(
                "Redfish log discovery exceeded 90 seconds; try a smaller log service".into(),
            );
        }
        safe_path(path)?;
        if self.host.is_empty()
            || self
                .host
                .contains(['/', '\\', '@', '"', '\r', '\n', ' ', '?', '#'])
        {
            return Err("Invalid BMC hostname".into());
        }
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.into()
        };
        let proxy = match crate::net::is_routed(self.host) {
            Ok(false) => None,
            Ok(true) => Some(crate::net::front_proxy().map_err(|e| format!("cannot start the route front end: {e}"))?),
            Err(e) => return Err(e),
        };
        let (args, config) = curl_request(
            &host,
            path,
            self.user,
            self.password,
            self.insecure,
            proxy.as_ref().map(|(u, c)| (u.as_str(), c.as_str())),
        );
        let mut command = crate::process::command("curl");
        command.args(&args);
        if proxy.is_some() {
            // Belt and braces with `noproxy = ""`: nothing in the environment
            // may redirect or exempt a routed request.
            for var in ["NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"] {
                command.env_remove(var);
            }
        }
        // The request's own limit plus time to start and reap curl.
        let limit = if proxy.is_some() { 35 } else { 15 };
        let sent = Instant::now();
        let text = run(command, Some(config), Duration::from_secs(limit)).map_err(|e| {
            if proxy.is_some() {
                with_route_cause(e, crate::net::front_error(self.host, sent))
            } else {
                e
            }
        })?;
        serde_json::from_str(&text).map_err(|_| "BMC returned invalid Redfish JSON".into())
    }
    fn members(&self, path: &str) -> Result<Vec<Value>, String> {
        collection(path, |path| self.get(path))
    }
    fn resolve(&self, item: Value) -> Result<Value, String> {
        if item.get("Message").is_none() && item.get("EntryType").is_none() {
            if let Some(path) = item["@odata.id"].as_str() {
                return self.get(path);
            }
        }
        Ok(item)
    }
}
fn collection(
    path: &str,
    mut get: impl FnMut(&str) -> Result<Value, String>,
) -> Result<Vec<Value>, String> {
    let mut next = path.to_owned();
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    loop {
        if !seen.insert(next.clone()) || seen.len() > 256 {
            return Err("Redfish pagination loop or page limit reached".into());
        }
        let page = get(&next)?;
        let members = page["Members"]
            .as_array()
            .ok_or("Redfish collection has no Members array")?;
        result.extend(members.iter().cloned());
        if result.len() > 65536 {
            return Err("Redfish entry limit reached".into());
        }
        match page["Members@odata.nextLink"].as_str() {
            Some(link) => next = safe_path(link)?.into(),
            None => break,
        }
    }
    Ok(result)
}
fn link<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value[key]["@odata.id"].as_str()
}
fn string(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or("").into()
}
fn redfish_entry(value: &Value, service: &str) -> Entry {
    Entry {
        id: string(value, "Id"),
        created: string(value, "Created"),
        source: service.into(),
        severity: string(value, "Severity"),
        message: value["Message"]
            .as_str()
            .or(value["Name"].as_str())
            .unwrap_or("No message reported")
            .into(),
    }
}

pub fn redfish(host: &str, user: &str, password: &str, insecure: bool) -> Result<Log, String> {
    let client = Client {
        host,
        user,
        password,
        insecure,
        started: Instant::now(),
    };
    let root = client.get("/redfish/v1/")?;
    let mut log = Log {
        source: "Redfish",
        ..Default::default()
    };
    let mut services = HashSet::new();
    for kind in ["Systems", "Managers", "Chassis"] {
        let Some(path) = link(&root, kind) else {
            continue;
        };
        let owners = match client.members(path) {
            Ok(items) => items,
            Err(e) => {
                log.warnings.push(format!("{kind}: {e}"));
                continue;
            }
        };
        for owner in owners {
            let owner = match owner["@odata.id"].as_str().map(|p| client.get(p)) {
                Some(Ok(v)) => v,
                Some(Err(e)) => {
                    log.warnings.push(e);
                    continue;
                }
                None => owner,
            };
            let Some(path) = link(&owner, "LogServices") else {
                continue;
            };
            let items = match client.members(path) {
                Ok(v) => v,
                Err(e) => {
                    log.warnings.push(e);
                    continue;
                }
            };
            for item in items {
                let Some(path) = item["@odata.id"].as_str() else {
                    continue;
                };
                if !services.insert(path.to_owned()) {
                    continue;
                }
                let read = || -> Result<Vec<Entry>, String> {
                    let service = client.get(path)?;
                    let entries =
                        link(&service, "Entries").ok_or("Log service has no Entries link")?;
                    client
                        .members(entries)?
                        .into_iter()
                        .map(|v| client.resolve(v).map(|v| redfish_entry(&v, path)))
                        .collect()
                };
                match read() {
                    Ok(entries) => log.entries.extend(entries),
                    Err(e) => log.warnings.push(format!("{path}: {e}")),
                }
            }
        }
    }
    if services.is_empty() {
        log.warnings.push(
            "No readable Redfish LogServices were advertised. Try IPMI SEL for older controllers."
                .into(),
        );
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routed_hosts_send_curl_through_the_front_end() {
        let (args, config) = curl_request("10.9.9.9", "/redfish/v1", "u", "p", false, Some(("socks5h://127.0.0.1:4000", "a:b")));
        assert!(!args.iter().any(|a| a == "--noproxy"), "--noproxy * would bypass the proxy");
        assert!(config.contains("noproxy = \"\"\n"), "NO_PROXY must not exempt the front end: {config}");
        assert!(config.contains("proxy = \"socks5h://127.0.0.1:4000\"\nproxy-user = \"a:b\"\n"), "{config}");
        assert!(args.windows(2).any(|w| w == ["--max-time", "30"]));
        let (args, config) = curl_request("10.9.9.9", "/redfish/v1", "u", "p", false, None);
        assert!(args.windows(2).any(|w| w == ["--noproxy", "*"]), "direct hosts ignore environment proxies");
        assert!(args.windows(2).any(|w| w == ["--max-time", "12"]), "direct bounds are unchanged");
        assert!(args.windows(2).any(|w| w == ["--connect-timeout", "4"]));
        assert!(!config.contains("proxy"));
    }
    #[test]
    fn credentials_stay_off_the_command_line() {
        let (args, config) = curl_request("10.9.9.9", "/redfish/v1", "u", "hunter2", false, Some(("socks5h://127.0.0.1:4000", "a:b")));
        for a in &args {
            assert!(!a.contains("hunter2") && !a.contains("u:hunter2") && !a.contains("a:b"), "argv leaks: {a}");
        }
        assert!(config.contains("user = \"u:hunter2\"\n"), "{config}");
    }
    #[test]
    fn routed_failures_name_the_route_cause() {
        assert_eq!(with_route_cause("curl: (97) SOCKS5 failure".into(), Some("hop refused".into())), "curl: (97) SOCKS5 failure (hop refused)");
        assert_eq!(with_route_cause("denied".into(), None), "denied");
    }
    #[cfg(unix)]
    // Drives `sh` and `sleep`, which a Windows machine need not have.
    #[cfg(unix)]
    #[test]
    fn command_reader_reports_failures_and_kills_timeouts() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'denied' >&2; exit 1"]);
        assert_eq!(
            run(command, None, Duration::from_secs(1)).unwrap_err(),
            "denied"
        );
        let mut command = Command::new("sleep");
        command.arg("2");
        let start = Instant::now();
        assert!(run(command, None, Duration::from_millis(50))
            .unwrap_err()
            .contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn redfish_links_stay_on_controller() {
        for path in [
            "https://elsewhere/redfish/v1/",
            "//elsewhere/",
            "/redfish/v1/../secret",
            "/redfish/v1/\r\n",
        ] {
            assert!(safe_path(path).is_err());
        }
        assert!(safe_path("/redfish/v1/Systems/1/LogServices/SEL/Entries?$skip=100").is_ok());
    }
    #[test]
    fn follows_pagination_and_rejects_loops() {
        let mut requests = Vec::new();
        let entries = collection("/redfish/v1/entries", |path| {
            requests.push(path.to_owned());
            Ok(if path.ends_with("?page=2") { serde_json::json!({"Members":[{"Id":"2"}]}) }
            else { serde_json::json!({"Members":[{"Id":"1"}],"Members@odata.nextLink":"/redfish/v1/entries?page=2"}) })
        }).unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(entries.len(), 2);
        assert!(collection("/redfish/v1/entries", |_| Ok(
            serde_json::json!({"Members":[],"Members@odata.nextLink":"/redfish/v1/entries"})
        ))
        .is_err());
        assert!(collection("/redfish/v1/entries", |_| Ok(
            serde_json::json!({"error":{}})
        ))
        .is_err());
    }
    #[test]
    fn redfish_event_fields() {
        let entry = redfish_entry(
            &serde_json::json!({"Id":"12","Created":"2026-09-28T10:50:00Z","Severity":"Warning","Message":"PSU redundancy lost"}),
            "SEL",
        );
        assert_eq!(entry.id, "12");
        assert_eq!(entry.severity, "Warning");
        assert_eq!(entry.message, "PSU redundancy lost");
    }
}

#[derive(Clone, Debug, Default)]
pub struct Sensor {
    pub name: String,
    pub reading: String,
    pub units: String,
    pub status: String,
    pub thresholds: String,
}
#[derive(Clone, Debug, Default)]
pub struct Sensors {
    pub source: &'static str,
    pub entries: Vec<Sensor>,
    pub warnings: Vec<String>,
}
/// Sensor readings over IPMI: the SDR repository for names, units and
/// thresholds, then Get Sensor Reading for each — `ipmitool sensor list`,
/// natively.
pub fn ipmi_sensors(host: &str, user: &str, password: &str) -> Result<Sensors, String> {
    let mut s = crate::ipmi::Session::open(host, user, password).map_err(|e| e.to_string())?;
    let sdr = crate::ipmi_records::read_sdr(&mut s).map_err(|e| e.to_string())?;
    let labels = [
        "Lower non-recoverable",
        "Lower critical",
        "Lower warning",
        "Upper warning",
        "Upper critical",
        "Upper non-recoverable",
    ];
    let entries = crate::ipmi_records::read_sensors(&mut s, &sdr)
        .into_iter()
        .map(|r| Sensor {
            name: r.name,
            reading: r.reading,
            units: r.units,
            status: r.status,
            thresholds: r
                .thresholds
                .iter()
                .zip(labels)
                .filter_map(|(v, k)| v.map(|v| format!("{k}: {v:.3}")))
                .collect::<Vec<_>>()
                .join("\n"),
        })
        .collect();
    Ok(Sensors { source: "IPMI", entries, warnings: vec![] })
}
fn sensor_value(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => "Not reported".into(),
    }
}
fn sensor(value: &Value, reading_key: &str, units: &str) -> Sensor {
    let status = [
        value["Status"]["Health"].as_str(),
        value["Status"]["State"].as_str(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" / ");
    let mut thresholds = Vec::new();
    for key in [
        "LowerThresholdNonCritical",
        "LowerThresholdCritical",
        "LowerThresholdFatal",
        "UpperThresholdNonCritical",
        "UpperThresholdCritical",
        "UpperThresholdFatal",
    ] {
        if !value[key].is_null() {
            thresholds.push(format!("{key}: {}", sensor_value(value, key)));
        }
    }
    if let Some(values) = value["Thresholds"].as_object() {
        for (key, val) in values {
            if !val["Reading"].is_null() {
                thresholds.push(format!("{key}: {}", sensor_value(val, "Reading")));
            }
        }
    }
    Sensor {
        name: value["Name"]
            .as_str()
            .or(value["Id"].as_str())
            .unwrap_or("Unnamed sensor")
            .into(),
        reading: sensor_value(value, reading_key),
        units: value["ReadingUnits"].as_str().unwrap_or(units).into(),
        status: if status.is_empty() {
            "Unknown".into()
        } else {
            status
        },
        thresholds: thresholds.join("\n"),
    }
}
pub fn redfish_sensors(
    host: &str,
    user: &str,
    password: &str,
    insecure: bool,
) -> Result<Sensors, String> {
    let client = Client {
        host,
        user,
        password,
        insecure,
        started: Instant::now(),
    };
    let root = client.get("/redfish/v1/")?;
    let path = link(&root, "Chassis")
        .ok_or("This controller does not advertise Redfish Chassis sensors")?;
    let mut result = Sensors {
        source: "Redfish",
        ..Default::default()
    };
    for member in client.members(path)? {
        let Some(path) = member["@odata.id"].as_str() else {
            continue;
        };
        let chassis = match client.get(path) {
            Ok(v) => v,
            Err(e) => {
                result.warnings.push(e);
                continue;
            }
        };
        if let Some(path) = link(&chassis, "Sensors") {
            match client.members(path) {
                Ok(members) => {
                    for member in members {
                        let value = match member["@odata.id"].as_str() {
                            Some(path) => client.get(path),
                            None => Ok(member),
                        };
                        match value {
                            Ok(v) => result.entries.push(sensor(&v, "Reading", "")),
                            Err(e) => result.warnings.push(e),
                        }
                    }
                }
                Err(e) => result.warnings.push(e),
            }
        }
        // Older Redfish implementations expose embedded Thermal and Power arrays.
        for (resource, arrays) in [
            (
                "Thermal",
                vec![
                    ("Temperatures", "ReadingCelsius", "°C"),
                    ("Fans", "Reading", ""),
                ],
            ),
            (
                "Power",
                vec![
                    ("Voltages", "ReadingVolts", "V"),
                    ("PowerControl", "PowerConsumedWatts", "W"),
                    ("PowerSupplies", "PowerOutputWatts", "W"),
                ],
            ),
        ] {
            let Some(path) = link(&chassis, resource) else {
                continue;
            };
            match client.get(path) {
                Ok(value) => {
                    for (array, reading, units) in arrays {
                        if let Some(items) = value[array].as_array() {
                            for item in items {
                                let entry = sensor(item, reading, units);
                                if !result
                                    .entries
                                    .iter()
                                    .any(|s| s.name == entry.name && s.units == entry.units)
                                {
                                    result.entries.push(entry);
                                }
                            }
                        }
                    }
                }
                Err(e) => result.warnings.push(format!("{resource}: {e}")),
            }
        }
    }
    if result.entries.is_empty() && result.warnings.is_empty() {
        result
            .warnings
            .push("No supported Redfish sensors advertised. Try IPMI sensors.".into());
    }
    Ok(result)
}

#[cfg(test)]
mod sensor_tests {
    use super::*;
    #[test]
    fn missing_redfish_reading_is_not_zero() {
        let item = sensor(
            &serde_json::json!({"Name":"CPU1", "Reading":null,"ReadingUnits":"Cel","Status":{"State":"Absent"}}),
            "Reading",
            "",
        );
        assert_eq!(item.reading, "Not reported");
        assert_eq!(item.status, "Absent");
    }
}

/// How a read uses the two protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Redfish,
    Ipmi,
    RedfishThenIpmi,
    IpmiThenRedfish,
}

/// What a source setting (0 Auto, 1 Redfish, 2 IPMI) means for a family.
/// Auto puts IPMI first on iLO 4: every Basic-auth Redfish request there
/// takes one of its few web sessions for 30 minutes, a log read pages through
/// many, and a full pool fails logins as a wrong password does. IPMI has no
/// such pool. Choosing Redfish outright still reads Redfish.
pub fn plan(source: usize, family: Option<Family>) -> Plan {
    match source {
        1 => Plan::Redfish,
        2 => Plan::Ipmi,
        _ if family == Some(Family::Ilo4) => Plan::IpmiThenRedfish,
        _ => Plan::RedfishThenIpmi,
    }
}

/// What the Auto setting is called for a family, since it differs.
pub fn auto_label(family: Option<Family>) -> &'static str {
    match plan(0, family) {
        Plan::IpmiThenRedfish => "Auto · IPMI first",
        _ => "Auto · Redfish first",
    }
}

// A valid empty log is a successful Redfish response. Missing/unreadable services
// trigger fallback, while useful partial results remain visible with warnings.
fn prefer_redfish<T>(
    preferred: Result<T, String>,
    fallback: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    match preferred {
        Ok(value) => Ok(value),
        Err(redfish_error) => fallback()
            .map_err(|ipmi_error| format!("Redfish: {redfish_error}\nIPMI fallback: {ipmi_error}")),
    }
}
/// `prefer_redfish` the other way round, for the families Auto reads over
/// IPMI first.
fn prefer_ipmi<T>(
    preferred: Result<T, String>,
    fallback: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    match preferred {
        Ok(value) => Ok(value),
        Err(ipmi_error) => fallback()
            .map_err(|redfish_error| format!("IPMI: {ipmi_error}\nRedfish fallback: {redfish_error}")),
    }
}
/// A log that came back empty but for warnings is a failure worth falling
/// back from, whichever protocol it came over.
fn usable_log(log: Log) -> Result<Log, String> {
    if log.entries.is_empty() && !log.warnings.is_empty() {
        Err(log.warnings.join("; "))
    } else {
        Ok(log)
    }
}
fn usable_sensors(sensors: Sensors) -> Result<Sensors, String> {
    if sensors.entries.is_empty() {
        Err(sensors.warnings.join("; "))
    } else {
        Ok(sensors)
    }
}
pub fn read_log(
    source: usize,
    family: Option<Family>,
    host: &str,
    user: &str,
    password: &str,
    insecure: bool,
) -> Result<Log, String> {
    match plan(source, family) {
        Plan::Ipmi => ipmi(host, user, password),
        Plan::Redfish => redfish(host, user, password, insecure),
        Plan::RedfishThenIpmi => prefer_redfish(
            redfish(host, user, password, insecure).and_then(usable_log),
            || ipmi(host, user, password),
        ),
        Plan::IpmiThenRedfish => prefer_ipmi(
            ipmi(host, user, password).and_then(usable_log),
            || redfish(host, user, password, insecure),
        ),
    }
}
pub fn read_sensors(
    source: usize,
    family: Option<Family>,
    host: &str,
    user: &str,
    password: &str,
    insecure: bool,
) -> Result<Sensors, String> {
    match plan(source, family) {
        Plan::Ipmi => ipmi_sensors(host, user, password),
        Plan::Redfish => redfish_sensors(host, user, password, insecure),
        Plan::RedfishThenIpmi => prefer_redfish(
            redfish_sensors(host, user, password, insecure).and_then(usable_sensors),
            || ipmi_sensors(host, user, password),
        ),
        Plan::IpmiThenRedfish => prefer_ipmi(
            ipmi_sensors(host, user, password).and_then(usable_sensors),
            || redfish_sensors(host, user, password, insecure),
        ),
    }
}
#[cfg(test)]
mod preference_tests {
    use super::*;

    #[test]
    fn auto_reads_ilo_over_ipmi_first() {
        // Each Basic-auth Redfish request costs iLO 4 a web session for 30
        // minutes, and a log read pages through many.
        assert_eq!(plan(0, Some(Family::Ilo4)), Plan::IpmiThenRedfish);
        assert_eq!(auto_label(Some(Family::Ilo4)), "Auto · IPMI first");
    }

    #[test]
    fn auto_reads_everyone_else_over_redfish_first() {
        for family in [Some(Family::Idrac9), Some(Family::Spx), Some(Family::Aten), None] {
            assert_eq!(plan(0, family), Plan::RedfishThenIpmi);
            assert_eq!(auto_label(family), "Auto · Redfish first");
        }
    }

    #[test]
    fn a_chosen_protocol_is_used_alone_whatever_the_family() {
        for family in [Some(Family::Ilo4), Some(Family::Idrac9), None] {
            assert_eq!(plan(1, family), Plan::Redfish);
            assert_eq!(plan(2, family), Plan::Ipmi);
        }
    }

    #[test]
    fn unavailable_ipmi_falls_back_to_redfish_and_both_errors_survive() {
        assert_eq!(prefer_ipmi(Ok(7), || panic!("unexpected Redfish request")).unwrap(), 7);
        assert_eq!(prefer_ipmi(Err("no answer on UDP 623".into()), || Ok(42)).unwrap(), 42);
        let failure = prefer_ipmi::<()>(Err("no answer on UDP 623".into()),
                                        || Err("HTTP 401".into())).unwrap_err();
        assert!(failure.starts_with("IPMI: no answer on UDP 623"), "{failure}");
        assert!(failure.contains("Redfish fallback: HTTP 401"), "{failure}");
    }
    #[test]
    fn redfish_success_including_empty_log_does_not_fall_back() {
        let log = prefer_redfish(Ok(Log::default()), || panic!("unexpected IPMI request")).unwrap();
        assert!(log.entries.is_empty());
    }
    #[test]
    fn unavailable_redfish_falls_back_and_both_errors_survive() {
        assert_eq!(
            prefer_redfish(Err("HTTP 404".into()), || Ok(42)).unwrap(),
            42
        );
        let failure = prefer_redfish::<()>(Err("HTTP 401".into()), || Err("IPMI disabled".into()))
            .unwrap_err();
        assert!(failure.contains("HTTP 401") && failure.contains("IPMI disabled"));
    }
}
