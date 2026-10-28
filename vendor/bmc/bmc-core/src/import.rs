//! Parsing for the import page: the hosts a CSV, a list, a CIDR block or an
//! address range names, before they are probed and saved.

use crate::hosts::Host;
use std::collections::BTreeSet;

/// An IP literal or a hostname: what a BMC address field takes, without a
/// URL scheme, a path or a port.
pub fn valid_address(address: &str) -> bool {
    let address = address.trim();
    !address.is_empty()
        && !address.contains(['/', ' ', '\t', '\n'])
        && (address.parse::<std::net::IpAddr>().is_ok()
            || address
                .split('.')
                .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')))
}
/// The hosts an import page's input names, in `mode`: 0 a CSV with an
/// `ipmi_ip` or `address` column (and optional `hostname`, `group`,
/// `datacenter`, `rack`, `tags`), 1 addresses separated by whitespace, 2 an
/// IPv4 CIDR block of /24 or smaller, 3 an IPv4 range `a-b`. At most 256,
/// each address once.
pub fn parse_import(input: &str, mode: usize) -> Result<Vec<Host>, String> {
    let parse_ip = |s: &str| {
        s.trim()
            .parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .map_err(|_| format!("Invalid IPv4 address: {s}"))
    };
    let mut hosts = Vec::new();
    match mode {
        3 => {
            let (a, b) = input
                .trim()
                .split_once('-')
                .ok_or("Use an IPv4 range, such as 10.20.1.11-10.20.1.50")?;
            let (a, b) = (parse_ip(a)?, parse_ip(b)?);
            if b < a || b - a > 255 {
                return Err("Choose 1–256 addresses".into());
            }
            for n in a..=b {
                hosts.push(Host {
                    address: std::net::Ipv4Addr::from(n).to_string(),
                    ..Default::default()
                });
            }
        }
        2 => {
            let (address, bits) = input
                .trim()
                .split_once('/')
                .ok_or("Use IPv4 CIDR notation, such as 10.20.1.0/28")?;
            let bits = bits.parse::<u32>().map_err(|_| "Invalid CIDR prefix")?;
            if !(24..=32).contains(&bits) {
                return Err("Use a /24–/32 network (up to 256 addresses)".into());
            }
            let size = 1u32 << (32 - bits);
            let start = parse_ip(address)? / size * size;
            let skip = if size > 2 { 1 } else { 0 };
            for n in skip..size - skip {
                hosts.push(Host {
                    address: std::net::Ipv4Addr::from(start + n).to_string(),
                    ..Default::default()
                });
            }
        }
        1 => {
            for address in input.split_whitespace() {
                if !valid_address(address) {
                    return Err(format!("Invalid address: {address}"));
                }
                hosts.push(Host {
                    address: address.into(),
                    ..Default::default()
                });
            }
        }
        _ => {
            let mut lines = input.lines();
            let header = csv_row(lines.next().ok_or("CSV is empty")?)?;
            let address_col = header
                .iter()
                .position(|h| h == "ipmi_ip" || h == "address")
                .ok_or("CSV needs an ipmi_ip or address column")?;
            for line in lines.filter(|l| !l.trim().is_empty()) {
                let cols = csv_row(line)?;
                let get = |name: &str| {
                    header
                        .iter()
                        .position(|h| h == name)
                        .and_then(|i| cols.get(i))
                        .cloned()
                        .unwrap_or_default()
                };
                let address = cols
                    .get(address_col)
                    .ok_or("CSV row is missing an address")?
                    .trim()
                    .to_owned();
                if !valid_address(&address) {
                    return Err(format!("Invalid address: {address}"));
                }
                hosts.push(Host {
                    name: get("hostname"),
                    address,
                    group: get("group"),
                    datacenter: get("datacenter"),
                    rack: get("rack"),
                    tags: get("tags"),
                    ..Default::default()
                });
            }
        }
    }
    if hosts.is_empty() || hosts.len() > 256 {
        return Err("Provide 1–256 addresses per import".into());
    }
    let mut seen = BTreeSet::new();
    hosts.retain(|h| seen.insert(h.address.to_lowercase()));
    Ok(hosts)
}
/// One CSV line's fields, trimmed; `""` inside quotes is a quote.
pub fn csv_row(line: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut value = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                value.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                values.push(value.trim().to_owned());
                value.clear();
            }
            _ => value.push(c),
        }
    }
    if quoted {
        return Err("Unterminated CSV quote; multiline fields are not supported".into());
    }
    values.push(value.trim().to_owned());
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_bounded_import_and_metadata() {
        let hosts=parse_import("hostname,ipmi_ip,datacenter,rack,tags\ncompute-09,10.20.1.19,London,LON-04,\"compute,production\"",0).unwrap();
        assert_eq!(hosts[0].tags, "compute,production");
        assert_eq!(hosts[0].rack, "LON-04");
        assert_eq!(parse_import("10.20.1.0/29", 2).unwrap().len(), 6);
        assert!(parse_import("10.0.0.0/16", 2).is_err());
        assert!(parse_import("10.0.0.8-10.0.0.1", 3).is_err());
        assert!(!valid_address("https://bmc.local"));
    }
}
