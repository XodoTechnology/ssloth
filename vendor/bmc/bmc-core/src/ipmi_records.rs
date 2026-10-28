//! The two record stores the host details page reads over IPMI: the Sensor
//! Data Record repository (names, units and conversion factors, then a reading
//! per sensor) and the System Event Log. Decoded here from the raw records, as
//! `ipmitool sensor list` and `sel elist` would, so neither needs `ipmitool`.
//!
//! Record layouts and the text tables are IPMI v2.0 §43 (SDR), §32 (SEL) and
//! §42 (sensor and event types). Only the parts a person reads are decoded;
//! OEM records are listed by number.

use crate::ipmi::{Error, Result, Session, NETFN_SENSOR, NETFN_STORAGE};
use std::collections::HashMap;

/// One sensor from the SDR repository, with what it takes to read it.
#[derive(Clone, Debug)]
pub struct SdrSensor {
    pub number: u8,
    pub lun: u8,
    pub name: String,
    pub event_type: u8,
    /// Event-only records name a sensor for the SEL but have no reading, and
    /// `sensor list` leaves them out.
    pub event_only: bool,
    /// Full records only; compact and event-only records have no conversion.
    pub conv: Option<Conversion>,
    /// Thresholds in the SDR, already converted: LNR, LC, LNC, UNC, UC, UNR.
    pub thresholds: [Option<f64>; 6],
}

/// `y = (M*x + B*10^Bexp) * 10^Rexp`, with x decoded per the analog format.
#[derive(Clone, Copy, Debug)]
pub struct Conversion {
    format: u8,
    m: i32,
    b: i32,
    b_exp: i32,
    r_exp: i32,
    linearization: u8,
    pub percentage: bool,
    pub unit: u8,
}

impl Conversion {
    pub fn apply(&self, raw: u8) -> Option<f64> {
        let x = match self.format {
            0 => raw as f64,
            1 => (if raw & 0x80 != 0 { -((!raw) as i32) } else { raw as i32 }) as f64,
            2 => (raw as i8) as f64,
            _ => return None, // no analog reading
        };
        let y = (self.m as f64 * x + self.b as f64 * 10f64.powi(self.b_exp))
            * 10f64.powi(self.r_exp);
        // Only linear sensors are converted exactly; the non-linear ones need
        // the named function applied, which a handful of BMCs use for fans.
        Some(match self.linearization & 0x7F {
            0 => y,
            1 => y.ln(),
            2 => y.log10(),
            3 => y.log2(),
            4 => y.exp(),
            5 => 10f64.powf(y),
            6 => 2f64.powf(y),
            7 => 1.0 / y,
            8 => y * y,
            9 => y * y * y,
            10 => y.sqrt(),
            11 => y.cbrt(),
            _ => y,
        })
    }
}

/// Sign-extend the low `bits` of `v`.
fn signed(v: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((v << shift) as i32) >> shift
}

fn id_string(rec: &[u8], at: usize) -> String {
    let Some(&tl) = rec.get(at) else { return String::new() };
    let len = (tl & 0x1F) as usize;
    let s = rec.get(at + 1..(at + 1 + len).min(rec.len())).unwrap_or(&[]);
    // 8-bit ASCII+Latin-1 is what BMCs use in practice; stop at a NUL.
    let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
    s[..end].iter().map(|c| *c as char).collect::<String>().trim().to_string()
}

/// Read every record in the SDR repository.
pub fn read_sdr(s: &mut Session) -> Result<Vec<SdrSensor>> {
    let mut out = Vec::new();
    let mut reservation = reserve(s)?;
    let mut id: u16 = 0;
    let mut guard = 0;
    while id != 0xFFFF && guard < 1024 {
        guard += 1;
        let (next, rec) = match get_sdr(s, reservation, id) {
            Ok(r) => r,
            // Another client touched the repository: reserve again and retry.
            Err(Error::Completion { code: 0xC5, .. }) => {
                reservation = reserve(s)?;
                continue;
            }
            Err(e) => return Err(e),
        };
        if let Some(sensor) = parse_sdr(&rec) {
            out.push(sensor);
        }
        if next == id {
            break;
        }
        id = next;
    }
    Ok(out)
}

fn reserve(s: &mut Session) -> Result<u16> {
    let r = s.call(NETFN_STORAGE, 0x22, &[])?;
    Ok(u16::from_le_bytes([*r.first().unwrap_or(&0), *r.get(1).unwrap_or(&0)]))
}

/// One record, in pieces: the 5-byte header, then the body 16 bytes at a time
/// — the size every BMC accepts, where larger reads are refused by some.
fn get_sdr(s: &mut Session, res: u16, id: u16) -> Result<(u16, Vec<u8>)> {
    let read = |s: &mut Session, off: u8, n: u8| -> Result<(u16, Vec<u8>)> {
        let mut d = res.to_le_bytes().to_vec();
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&[off, n]);
        let r = s.call(NETFN_STORAGE, 0x23, &d)?;
        if r.len() < 2 {
            return Err(Error::Protocol("short SDR response".into()));
        }
        Ok((u16::from_le_bytes([r[0], r[1]]), r[2..].to_vec()))
    };
    let (next, head) = read(s, 0, 5)?;
    if head.len() < 5 {
        return Err(Error::Protocol("short SDR header".into()));
    }
    let len = head[4] as usize;
    let mut rec = head;
    while rec.len() < 5 + len {
        let want = (5 + len - rec.len()).min(16) as u8;
        let (_, part) = read(s, rec.len() as u8, want)?;
        if part.is_empty() {
            break;
        }
        rec.extend_from_slice(&part);
    }
    Ok((next, rec))
}

fn parse_sdr(rec: &[u8]) -> Option<SdrSensor> {
    let ty = *rec.get(3)?;
    match ty {
        // Full sensor record.
        0x01 if rec.len() >= 48 => {
            let format = rec[20] >> 6;
            let conv = Conversion {
                format,
                m: signed(rec[24] as u32 | ((rec[25] as u32 >> 6) << 8), 10),
                b: signed(rec[26] as u32 | ((rec[27] as u32 >> 6) << 8), 10),
                r_exp: signed((rec[29] >> 4) as u32, 4),
                b_exp: signed((rec[29] & 0x0F) as u32, 4),
                linearization: rec[23],
                percentage: rec[20] & 1 != 0,
                unit: rec[21],
            };
            // Readable threshold mask, bits 0..5: LNC LC LNR UNC UC UNR.
            let readable = rec[18];
            let t = |bit: u8, at: usize| {
                if readable & (1 << bit) != 0 { conv.apply(rec[at]) } else { None }
            };
            let threshold = rec[13] == 0x01;
            Some(SdrSensor {
                number: rec[7],
                lun: rec[6] & 3,
                name: id_string(rec, 47),
                event_type: rec[13],
                event_only: false,
            conv: (format != 3).then_some(conv),
                thresholds: if threshold {
                    [t(2, 39), t(1, 40), t(0, 41), t(3, 38), t(4, 37), t(5, 36)]
                } else {
                    [None; 6]
                },
            })
        }
        // Compact sensor record: discrete, no conversion.
        0x02 if rec.len() >= 32 => Some(SdrSensor {
            number: rec[7],
            lun: rec[6] & 3,
            name: id_string(rec, 31),
            event_type: rec[13],
            event_only: false,
            conv: None,
            thresholds: [None; 6],
        }),
        // Event-only: no reading, but the SEL names its events by it.
        0x03 if rec.len() >= 17 => Some(SdrSensor {
            number: rec[7],
            lun: rec[6] & 3,
            name: id_string(rec, 16),
            event_type: rec[11],
            event_only: true,
            conv: None,
            thresholds: [None; 6],
        }),
        _ => None,
    }
}

/// One line of `sensor list`.
#[derive(Clone, Debug)]
pub struct Reading {
    pub name: String,
    /// The value, or "na" when the BMC has none.
    pub reading: String,
    pub units: String,
    /// ok / nc / cr / nr for threshold sensors, the state bits for discrete.
    pub status: String,
    pub thresholds: [Option<f64>; 6],
}

pub fn read_sensors(s: &mut Session, sdr: &[SdrSensor]) -> Vec<Reading> {
    let mut out = Vec::new();
    for sensor in sdr.iter().filter(|s| !s.event_only) {
        let r = s.call_lun(NETFN_SENSOR, sensor.lun, 0x2D, &[sensor.number]).ok();
        // Byte 1 bit 5: reading unavailable; bit 6 clear: scanning disabled.
        let available = r.as_ref().is_some_and(|r| r.len() >= 2 && r[1] & 0x20 == 0 && r[1] & 0x40 != 0);
        let threshold = sensor.event_type == 0x01;
        let (reading, units, status) = match (&sensor.conv, threshold, available, &r) {
            (Some(conv), true, true, Some(r)) => {
                let value = conv.apply(r[0]);
                let bits = r.get(2).copied().unwrap_or(0);
                let status = if bits & 0x24 != 0 { "nr" } else if bits & 0x12 != 0 { "cr" }
                    else if bits & 0x09 != 0 { "nc" } else { "ok" };
                (value.map(|v| format!("{v:.3}")).unwrap_or_else(|| "na".into()),
                 unit_name(conv), status.to_string())
            }
            (_, false, true, Some(r)) => {
                // Both state bytes as they arrive, as `ipmitool` prints them
                // (so the reserved high bit of the second shows as 0x80).
                let (b2, b3) = (r.get(2).copied().unwrap_or(0), r.get(3).copied().unwrap_or(0));
                ("0x0".into(), "discrete".into(), format!("0x{b2:02x}{b3:02x}"))
            }
            (Some(conv), true, false, _) => ("na".into(), unit_name(conv), "na".into()),
            _ if r.is_none() => continue, // event-only or unreadable: nothing to list
            _ => ("na".into(), "discrete".into(), "na".into()),
        };
        out.push(Reading {
            name: sensor.name.clone(),
            reading,
            units,
            status,
            thresholds: sensor.thresholds,
        });
    }
    out
}

fn unit_name(c: &Conversion) -> String {
    if c.percentage {
        return "percent".into();
    }
    const UNITS: [&str; 42] = [
        "unspecified", "degrees C", "degrees F", "degrees K", "Volts", "Amps", "Watts",
        "Joules", "Coulombs", "VA", "Nits", "lumen", "lux", "Candela", "kPa", "PSI",
        "Newton", "CFM", "RPM", "Hz", "microsecond", "millisecond", "second", "minute",
        "hour", "day", "week", "mil", "inches", "feet", "cu in", "cu feet", "mm", "cm",
        "m", "cu cm", "cu m", "liters", "fluid ounce", "radians", "steradians",
        "revolutions",
    ];
    UNITS.get(c.unit as usize).map(|s| s.to_string()).unwrap_or_else(|| format!("unit {}", c.unit))
}

// ---------- SEL ----------

/// One line of `sel elist`.
#[derive(Clone, Debug)]
pub struct SelEntry {
    pub id: u16,
    /// ISO 8601 UTC, "Pre-Init" before the clock was set, or empty for
    /// non-timestamped OEM records.
    pub time: String,
    /// Sensor type and name, e.g. "Power Supply PSU1".
    pub sensor: String,
    pub event: String,
    /// "Asserted" / "Deasserted" for system events.
    pub direction: String,
}

pub fn read_sel(s: &mut Session, sdr: &[SdrSensor]) -> Result<Vec<SelEntry>> {
    let names: HashMap<u8, &str> = sdr.iter().map(|x| (x.number, x.name.as_str())).collect();
    let info = s.call(NETFN_STORAGE, 0x40, &[])?;
    let count = u16::from_le_bytes([*info.get(1).unwrap_or(&0), *info.get(2).unwrap_or(&0)]);
    let mut out = Vec::new();
    if count == 0 {
        return Ok(out);
    }
    let mut id: u16 = 0;
    let mut guard = 0;
    while id != 0xFFFF && guard < 8192 {
        guard += 1;
        let mut d = vec![0, 0];
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&[0, 0xFF]);
        let r = s.call(NETFN_STORAGE, 0x43, &d)?;
        if r.len() < 18 {
            break;
        }
        let next = u16::from_le_bytes([r[0], r[1]]);
        out.push(decode_sel(&r[2..18], &names));
        if next == id {
            break;
        }
        id = next;
    }
    Ok(out)
}

fn decode_sel(rec: &[u8], names: &HashMap<u8, &str>) -> SelEntry {
    let id = u16::from_le_bytes([rec[0], rec[1]]);
    let ty = rec[2];
    let ts = u32::from_le_bytes([rec[3], rec[4], rec[5], rec[6]]);
    if ty >= 0xE0 {
        return SelEntry { id, time: String::new(), sensor: "OEM".into(),
            event: format!("OEM record {ty:#04x}: {}", hex(&rec[3..])), direction: String::new() };
    }
    let time = timestamp(ts);
    if ty >= 0xC0 {
        return SelEntry { id, time, sensor: "OEM".into(),
            event: format!("OEM record {ty:#04x}: {}", hex(&rec[10..])), direction: String::new() };
    }
    let stype = rec[10];
    let num = rec[11];
    let dir = if rec[12] & 0x80 != 0 { "Deasserted" } else { "Asserted" };
    let etype = rec[12] & 0x7F;
    let offset = rec[13] & 0x0F;
    // As `ipmitool` prints it: the name when the SDR has one, the bare type
    // when it has the sensor unnamed, the number when it has no record at all.
    let sensor = match names.get(&num) {
        Some(n) if !n.is_empty() => format!("{} {n}", sensor_type_name(stype)),
        Some(_) => sensor_type_name(stype),
        None => format!("{} #{num:#04x}", sensor_type_name(stype)),
    };
    SelEntry { id, time, sensor, event: event_text(stype, etype, offset), direction: dir.into() }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn timestamp(ts: u32) -> String {
    // Below 0x20000000 the clock was never set: seconds since BMC init.
    if ts < 0x2000_0000 {
        return "Pre-Init".into();
    }
    let t = ts as i64;
    let (y, m, d) = civil(t.div_euclid(86400));
    let s = t.rem_euclid(86400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
}

fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

fn sensor_type_name(t: u8) -> String {
    const TYPES: [&str; 45] = [
        "Reserved", "Temperature", "Voltage", "Current", "Fan", "Physical Security",
        "Platform Security", "Processor", "Power Supply", "Power Unit", "Cooling Device",
        "Other", "Memory", "Drive Slot / Bay", "POST Memory Resize", "System Firmware",
        "Event Logging Disabled", "Watchdog1", "System Event", "Critical Interrupt", "Button",
        "Module / Board", "Microcontroller", "Add-in Card", "Chassis", "Chip Set", "Other FRU",
        "Cable / Interconnect", "Terminator", "System Boot Initiated", "Boot Error", "OS Boot",
        "OS Critical Stop", "Slot / Connector", "System ACPI Power State", "Watchdog2",
        "Platform Alert", "Entity Presence", "Monitor ASIC", "LAN", "Management Subsys Health",
        "Battery", "Session Audit", "Version Change", "FRU State",
    ];
    match TYPES.get(t as usize) {
        Some(s) => s.to_string(),
        None if t >= 0xC0 => format!("OEM {t:#04x}"),
        None => format!("Type {t:#04x}"),
    }
}

/// The event text for an offset, from the threshold, generic or
/// sensor-specific tables.
fn event_text(stype: u8, etype: u8, offset: u8) -> String {
    let o = offset as usize;
    let table: &[&str] = match etype {
        0x01 => &[
            "Lower Non-critical going low", "Lower Non-critical going high",
            "Lower Critical going low", "Lower Critical going high",
            "Lower Non-recoverable going low", "Lower Non-recoverable going high",
            "Upper Non-critical going low", "Upper Non-critical going high",
            "Upper Critical going low", "Upper Critical going high",
            "Upper Non-recoverable going low", "Upper Non-recoverable going high",
        ],
        0x02 => &["Transition to Idle", "Transition to Active", "Transition to Busy"],
        0x03 => &["State Deasserted", "State Asserted"],
        0x04 => &["Predictive Failure deasserted", "Predictive Failure asserted"],
        0x05 => &["Limit Not Exceeded", "Limit Exceeded"],
        0x06 => &["Performance Met", "Performance Lags"],
        0x07 => &[
            "Transition to OK", "Transition to Non-critical from OK",
            "Transition to Critical from less severe", "Transition to Non-recoverable from less severe",
            "Transition to Non-critical from more severe", "Transition to Critical from Non-recoverable",
            "Transition to Non-recoverable", "Monitor", "Informational",
        ],
        0x08 => &["Device Absent", "Device Present"],
        0x09 => &["Device Disabled", "Device Enabled"],
        0x0A => &[
            "Transition to Running", "Transition to In Test", "Transition to Power Off",
            "Transition to On Line", "Transition to Off Line", "Transition to Off Duty",
            "Transition to Degraded", "Transition to Power Save", "Install Error",
        ],
        0x0B => &[
            "Fully Redundant", "Redundancy Lost", "Redundancy Degraded",
            "Non-redundant: Sufficient from Redundant", "Non-redundant: Sufficient from Insufficient",
            "Non-redundant: Insufficient Resources", "Redundancy Degraded from Fully Redundant",
            "Redundancy Degraded from Non-redundant",
        ],
        0x0C => &["D0 Power State", "D1 Power State", "D2 Power State", "D3 Power State"],
        0x6F => sensor_specific(stype),
        _ => &[],
    };
    match table.get(o) {
        Some(s) => s.to_string(),
        None => format!("Event type {etype:#04x}, offset {offset:#x}"),
    }
}

fn sensor_specific(stype: u8) -> &'static [&'static str] {
    match stype {
        0x05 => &["General Chassis intrusion", "Drive Bay intrusion", "I/O Card area intrusion",
            "Processor area intrusion", "System unplugged from LAN", "Unauthorized dock",
            "FAN area intrusion"],
        0x07 => &["IERR", "Thermal Trip", "FRB1/BIST failure", "FRB2/Hang in POST failure",
            "FRB3/Processor Startup/Init failure", "Configuration Error",
            "SM BIOS Uncorrectable CPU-complex Error", "Presence detected", "Disabled",
            "Terminator presence detected", "Throttled", "Uncorrectable machine check exception",
            "Correctable machine check error"],
        0x08 => &["Presence detected", "Failure detected", "Predictive failure",
            "Power Supply AC lost", "AC lost or out-of-range", "AC out-of-range, but present",
            "Config Error"],
        0x09 => &["Power off/down", "Power cycle", "240VA power down", "Interlock power down",
            "AC lost", "Soft-power control failure", "Failure detected", "Predictive failure"],
        0x0C => &["Correctable ECC", "Uncorrectable ECC", "Parity", "Memory Scrub Failed",
            "Memory Device Disabled", "Correctable ECC logging limit reached", "Presence Detected",
            "Configuration Error", "Spare", "Throttled", "Critical Overtemperature"],
        0x0D => &["Drive Present", "Drive Fault", "Predictive Failure", "Hot Spare",
            "Parity Check In Progress", "In Critical Array", "In Failed Array",
            "Rebuild In Progress", "Rebuild Aborted"],
        0x0F => &["System Firmware Error", "System Firmware Hang", "System Firmware Progress"],
        0x10 => &["Correctable memory error logging disabled", "Event logging disabled",
            "Log area reset/cleared", "All event logging disabled", "Log full", "Log almost full"],
        0x11 => &["BIOS Reset", "OS Reset", "OS Shut Down", "OS Power Down", "OS Power Cycle",
            "OS NMI/Diag Interrupt", "OS Expired", "OS pre-timeout Interrupt"],
        0x12 => &["System Reconfigured", "OEM System boot event",
            "Undetermined system hardware failure", "Entry added to auxiliary log", "PEF Action",
            "Timestamp Clock Sync"],
        0x13 => &["Front Panel NMI", "Bus Timeout", "I/O Channel check NMI", "Software NMI",
            "PCI PERR", "PCI SERR", "EISA failsafe timeout", "Bus Correctable error",
            "Bus Uncorrectable error", "Fatal NMI", "Bus Fatal Error", "Bus Degraded"],
        0x14 => &["Power Button pressed", "Sleep Button pressed", "Reset Button pressed",
            "FRU Latch", "FRU Service"],
        0x1D => &["Initiated by power up", "Initiated by hard reset", "Initiated by warm reset",
            "User requested PXE boot", "Automatic boot to diagnostic", "OS initiated hard reset",
            "OS initiated warm reset", "System Restart"],
        0x1F => &["A: boot completed", "C: boot completed", "PXE boot completed",
            "Diagnostic boot completed", "CD-ROM boot completed", "ROM boot completed",
            "boot completed - device not specified"],
        0x20 => &["Stop during OS load/init", "Run-time stop", "OS graceful stop",
            "OS graceful shutdown", "PEF initiated soft shutdown", "Agent not responding"],
        0x22 => &["S0/G0: working", "S1: sleeping with system hw & processor context maintained",
            "S2: sleeping, processor context lost", "S3: sleeping, processor & hw context lost, memory retained",
            "S4: non-volatile sleep/suspend-to-disk", "S5/G2: soft-off", "S4/S5: soft-off",
            "G3: mechanical off", "Sleeping in S1/S2/S3", "G1: sleeping",
            "S5: entered by override", "Legacy ON state", "Legacy OFF state", "Unknown"],
        0x23 => &["Timer expired", "Hard reset", "Power down", "Power cycle", "reserved",
            "reserved", "reserved", "reserved", "Timer interrupt"],
        0x25 => &["Present", "Absent", "Disabled"],
        0x2A => &["Session activated", "Session deactivated", "Invalid username or password",
            "Invalid password disable"],
        0x2B => &["Hardware change detected", "Firmware or software change detected",
            "Hardware incompatibility detected", "Firmware or software incompatibility detected",
            "Invalid or unsupported hardware version", "Invalid or unsupported firmware or software version",
            "Hardware change success", "Firmware or software change success"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full sensor record (§43.1) with y = x: M = 1, B = 0, no exponents.
    fn full_record(number: u8, name: &str) -> Vec<u8> {
        let mut rec = vec![0u8; 48];
        rec[3] = 0x01;
        rec[7] = number;
        rec[13] = 0x01; // threshold
        rec[24] = 1;
        rec[47] = 0xC0 | name.len() as u8; // 8-bit ASCII + Latin-1
        rec.extend_from_slice(name.as_bytes());
        rec
    }

    /// A system event record (§32.1) from generator 0x20, EvM revision 4.
    fn sel(ty: u8, ts: u32, stype: u8, num: u8, dir_type: u8, data1: u8) -> Vec<u8> {
        let mut rec = vec![0x01, 0x00, ty];
        rec.extend_from_slice(&ts.to_le_bytes());
        rec.extend_from_slice(&[0x20, 0x00, 0x04, stype, num, dir_type, data1, 0xFF, 0xFF]);
        rec
    }

    #[test]
    fn full_record_reads_name_unit_and_readable_thresholds() {
        let mut rec = full_record(0x30, "CPU1 Temp");
        rec[21] = 1; // degrees C
        rec[18] = 0b11_1011; // everything readable but LNR
        rec[36..42].copy_from_slice(&[95, 90, 85, 0, 5, 10]); // UNR UC UNC LNR LC LNC
        let s = parse_sdr(&rec).unwrap();
        assert_eq!((s.number, s.name.as_str(), s.event_only), (0x30, "CPU1 Temp", false));
        assert_eq!(s.thresholds, [None, Some(5.), Some(10.), Some(85.), Some(90.), Some(95.)]);
        let conv = s.conv.unwrap();
        assert_eq!(unit_name(&conv), "degrees C");
        assert_eq!(conv.apply(42), Some(42.));
    }

    #[test]
    fn conversion_takes_ten_bit_factors_and_signed_exponents() {
        let mut rec = full_record(0x10, "12V");
        rec[21] = 4; // Volts
        // M = 500 and B = -2, each split 8 + 2 bits; R exp -4, B exp 2.
        (rec[24], rec[25]) = (0xF4, 0x40);
        (rec[26], rec[27]) = (0xFE, 0xC0);
        rec[29] = 0xC2;
        let conv = parse_sdr(&rec).unwrap().conv.unwrap();
        assert_eq!(unit_name(&conv), "Volts");
        // (500 × 240 − 2 × 10²) × 10⁻⁴
        assert!((conv.apply(240).unwrap() - 11.98).abs() < 1e-9);
    }

    #[test]
    fn analog_formats_and_percentages() {
        let mut rec = full_record(0x11, "Inlet");
        rec[20] = 0x40; // one's complement
        assert_eq!(parse_sdr(&rec).unwrap().conv.unwrap().apply(0xF5), Some(-10.));
        rec[20] = 0x80; // two's complement
        assert_eq!(parse_sdr(&rec).unwrap().conv.unwrap().apply(0xF6), Some(-10.));
        rec[20] = 0x01; // unsigned, percentage
        assert_eq!(unit_name(&parse_sdr(&rec).unwrap().conv.unwrap()), "percent");
        rec[20] = 0xC0; // no analog reading at all
        assert!(parse_sdr(&rec).unwrap().conv.is_none());
    }

    #[test]
    fn event_only_record_names_a_sensor_without_a_reading() {
        let mut rec = vec![0u8; 16];
        (rec[3], rec[7], rec[11]) = (0x03, 0x52, 0x6F);
        rec.push(0xC0 | 4);
        rec.extend_from_slice(b"PSU2");
        let s = parse_sdr(&rec).unwrap();
        assert_eq!((s.number, s.name.as_str(), s.event_only), (0x52, "PSU2", true));
        assert!(s.conv.is_none());
    }

    #[test]
    fn sel_reads_like_sel_elist() {
        let names = HashMap::from([(0x30, "CPU1 Temp"), (0x41, "")]);
        let e = decode_sel(&sel(0x02, 0x6ABA_4658, 0x01, 0x30, 0x01, 0x59), &names);
        assert_eq!(e.time, "2026-09-28T10:50:00Z");
        assert_eq!(e.sensor, "Temperature CPU1 Temp");
        assert_eq!(e.event, "Upper Critical going high");
        assert_eq!(e.direction, "Asserted");
        let e = decode_sel(&sel(0x02, 0x6ABA_4658, 0x01, 0x30, 0x81, 0x59), &names);
        assert_eq!(e.direction, "Deasserted");
        // Sensor-specific offsets; an SDR entry without a name; no entry at all.
        let e = decode_sel(&sel(0x02, 0x6ABA_4658, 0x08, 0x41, 0x6F, 0x03), &names);
        assert_eq!((e.sensor.as_str(), e.event.as_str()), ("Power Supply", "Power Supply AC lost"));
        let e = decode_sel(&sel(0x02, 0x6ABA_4658, 0x08, 0x40, 0x6F, 0x03), &names);
        assert_eq!(e.sensor, "Power Supply #0x40");
        let e = decode_sel(&sel(0x02, 0x6ABA_4658, 0x01, 0x30, 0x01, 0x0C), &names);
        assert_eq!(e.event, "Event type 0x01, offset 0xc");
    }

    #[test]
    fn sel_keeps_oem_records_and_unset_clocks() {
        let none = HashMap::new();
        let e = decode_sel(&sel(0xC1, 0x6ABA_4658, 0x01, 0x30, 0x01, 0x59), &none);
        assert_eq!((e.sensor.as_str(), e.time.as_str()), ("OEM", "2026-09-28T10:50:00Z"));
        assert_eq!(e.event, "OEM record 0xc1: 01 30 01 59 ff ff");
        let e = decode_sel(&sel(0xE0, 0x6ABA_4658, 0x01, 0x30, 0x01, 0x59), &none);
        assert_eq!(e.time, "");
        assert_eq!(e.event, "OEM record 0xe0: 58 46 ba 6a 20 00 04 01 30 01 59 ff ff");
        assert_eq!(decode_sel(&sel(0x02, 0x100, 0x01, 0x30, 0x01, 0x59), &none).time, "Pre-Init");
        assert_eq!(timestamp(0x38BC_5D7F), "2000-02-29T23:59:59Z");
    }
}
