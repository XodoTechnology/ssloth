//! BMC family metadata and detection.
//!
//! A family selects the console transport, input encoding, power path, and
//! virtual-media implementation used by the rest of the application.

pub mod aten;
pub mod avocent;
pub mod idrac;
pub mod idrac8;
pub mod ilo4;
pub mod probe;
pub mod quanta;
pub mod spx;

/// A supported BMC hardware/firmware family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// Supermicro/ATEN: InsydeVNC on :5900, SCSI vmedia on :623.
    Aten,
    /// Quanta/AMI MegaRAC: JViewer IVTP on :7578, IUSB vmedia on :5120.
    Quanta,
    /// HP iLO 4: Integrated Remote Console over WebSocket, URL-based vmedia.
    Ilo4,
    /// Dell iDRAC 9: standard RFB over WebSocket, Redfish for everything else.
    Idrac9,
    /// Dell iDRAC 7/8: Avocent APCP/AVSP on :5900 with DVC video, AVMP vmedia.
    Idrac8,
    /// ASRock Rack and other AMI MegaRAC SP-X OEMs.
    Spx,
    /// Gigabyte boards running Avocent MergePoint EMS.
    Avocent,
}

impl Family {
    pub const ALL: [Family; 7] = [
        Family::Aten,
        Family::Quanta,
        Family::Ilo4,
        Family::Idrac9,
        Family::Idrac8,
        Family::Spx,
        Family::Avocent,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Family::Aten => "Supermicro / ATEN",
            Family::Quanta => "Quanta / AMI MegaRAC",
            Family::Ilo4 => "HP iLO 4",
            Family::Idrac9 => "Dell iDRAC 9",
            Family::Idrac8 => "Dell iDRAC 8",
            Family::Spx => "ASRock Rack / AMI SP-X",
            Family::Avocent => "Gigabyte / Avocent MergePoint",
        }
    }

    /// A colour per family, so badges are distinguishable at a glance. Plain
    /// RGB, so the protocol side carries no GUI toolkit.
    pub fn tint(self) -> [u8; 3] {
        match self {
            Family::Aten => [0x6C, 0xA8, 0x6C],
            Family::Quanta => [0xC2, 0x8B, 0x5E],
            Family::Ilo4 => [0x5A, 0xA9, 0xC4],
            Family::Idrac9 => [0x8C, 0x8C, 0xD4],
            Family::Idrac8 => [0x7A, 0x9A, 0xC8],
            Family::Spx => [0xC9, 0x6A, 0x6A],
            Family::Avocent => [0xB9, 0x9A, 0x5E],
        }
    }

    /// Stable name for the inventory file. Distinct from [`Family::label`],
    /// which may be reworded without invalidating saved hosts.
    pub fn key(self) -> &'static str {
        match self {
            Family::Aten => "aten",
            Family::Quanta => "quanta",
            Family::Ilo4 => "ilo4",
            Family::Idrac9 => "idrac9",
            Family::Idrac8 => "idrac8",
            Family::Spx => "spx",
            Family::Avocent => "avocent",
        }
    }

    pub fn from_key(key: &str) -> Option<Family> {
        Family::ALL.into_iter().find(|family| family.key() == key)
    }
}

/// Who made the machine. Usually implied by the family, but not always: the
/// Avocent MergePoint firmware runs on Gigabyte boards *and* on Dell PowerEdge
/// C, and AMI's firmware — both generations — is sold under a dozen brands.
/// The family decides the protocol; the vendor only decides the name and mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Vendor {
    Supermicro,
    /// AMI's own, for AMI firmware whose brand is not known yet.
    Ami,
    Hp,
    Dell,
    Asrock,
    Gigabyte,
    Asus,
    Lenovo,
    Intel,
    Tyan,
    Quanta,
    Inspur,
}

impl Vendor {
    pub const ALL: [Vendor; 12] = [
        Vendor::Supermicro, Vendor::Ami, Vendor::Hp, Vendor::Dell, Vendor::Asrock,
        Vendor::Gigabyte, Vendor::Asus, Vendor::Lenovo, Vendor::Intel, Vendor::Tyan,
        Vendor::Quanta, Vendor::Inspur,
    ];

    /// Stable name for the inventory file.
    pub fn key(self) -> &'static str {
        match self {
            Vendor::Supermicro => "supermicro",
            Vendor::Ami => "ami",
            Vendor::Hp => "hp",
            Vendor::Dell => "dell",
            Vendor::Asrock => "asrock",
            Vendor::Gigabyte => "gigabyte",
            Vendor::Asus => "asus",
            Vendor::Lenovo => "lenovo",
            Vendor::Intel => "intel",
            Vendor::Tyan => "tyan",
            Vendor::Quanta => "quanta",
            Vendor::Inspur => "inspur",
        }
    }

    pub fn from_key(key: &str) -> Option<Vendor> {
        Vendor::ALL.into_iter().find(|v| v.key() == key)
    }

    /// The name people know the brand by.
    pub fn name(self) -> &'static str {
        match self {
            Vendor::Supermicro => "Supermicro",
            Vendor::Ami => "AMI",
            Vendor::Hp => "HP",
            Vendor::Dell => "Dell",
            Vendor::Asrock => "ASRock Rack",
            Vendor::Gigabyte => "Gigabyte",
            Vendor::Asus => "ASUS",
            Vendor::Lenovo => "Lenovo",
            Vendor::Intel => "Intel",
            Vendor::Tyan => "Tyan",
            Vendor::Quanta => "Quanta",
            Vendor::Inspur => "Inspur",
        }
    }

    /// Recognise a Redfish `Manufacturer` (or a page title). Vendors spell
    /// themselves every which way — "ASRockRack", "ASUSTeK COMPUTER INC.",
    /// "GIGA-BYTE TECHNOLOGY" — so this matches on a lower-cased fragment.
    pub fn from_manufacturer(s: &str) -> Option<Vendor> {
        let l = s.to_ascii_lowercase();
        let has = |f: &str| l.contains(f);
        Some(if has("asrock") { Vendor::Asrock }
            else if has("giga") { Vendor::Gigabyte }
            else if has("asus") { Vendor::Asus }
            else if has("lenovo") { Vendor::Lenovo }
            else if has("intel") { Vendor::Intel }
            else if has("tyan") || has("mitac") { Vendor::Tyan }
            else if has("quanta") || has("qct") { Vendor::Quanta }
            else if has("inspur") { Vendor::Inspur }
            else if has("supermicro") || has("super micro") { Vendor::Supermicro }
            else if has("dell") { Vendor::Dell }
            else if has("hewlett") || has("hpe") || l.trim() == "hp" { Vendor::Hp }
            else { return None })
    }

    /// Recognise an IANA enterprise number from IPMI Get Device ID. AMI's own
    /// (20974) is left out on purpose: many boards never replace it, and it
    /// says only what the family already says.
    pub fn from_iana(id: u32) -> Option<Vendor> {
        Some(match id {
            10876 => Vendor::Supermicro,
            11 => Vendor::Hp,
            674 => Vendor::Dell,
            49622 => Vendor::Asrock,
            15370 => Vendor::Gigabyte,
            2623 => Vendor::Asus,
            19046 => Vendor::Lenovo,
            343 => Vendor::Intel,
            6653 => Vendor::Tyan,
            7244 => Vendor::Quanta,
            37945 => Vendor::Inspur,
            _ => return None,
        })
    }

    /// The vendor's mark, as a white-on-black mask (see assets/icons/README.md).
    /// Brands with no mark here use AMI's, since what they run is AMI's.
    pub fn logo_png(self) -> &'static [u8] {
        match self {
            Vendor::Supermicro => include_bytes!("../../../../assets/icons/aten.png"),
            Vendor::Hp => include_bytes!("../../../../assets/icons/ilo.png"),
            Vendor::Dell => include_bytes!("../../../../assets/icons/idrac.png"),
            Vendor::Asrock => include_bytes!("../../../../assets/icons/asrock.png"),
            Vendor::Gigabyte => include_bytes!("../../../../assets/icons/gigabyte.png"),
            Vendor::Asus => include_bytes!("../../../../assets/icons/asus.png"),
            Vendor::Lenovo => include_bytes!("../../../../assets/icons/lenovo.png"),
            Vendor::Intel => include_bytes!("../../../../assets/icons/intel.png"),
            Vendor::Ami | Vendor::Tyan | Vendor::Quanta | Vendor::Inspur => {
                include_bytes!("../../../../assets/icons/ami.png")
            }
        }
    }

    /// A colour per vendor, so badges are distinguishable at a glance.
    pub fn tint(self) -> [u8; 3] {
        match self {
            Vendor::Supermicro => Family::Aten.tint(),
            Vendor::Ami | Vendor::Quanta => Family::Quanta.tint(),
            Vendor::Hp => Family::Ilo4.tint(),
            Vendor::Dell => Family::Idrac9.tint(),
            Vendor::Asrock => Family::Spx.tint(),
            Vendor::Gigabyte => Family::Avocent.tint(),
            Vendor::Asus => [0x7A, 0x9C, 0xD8],
            Vendor::Lenovo => [0xD8, 0x6A, 0x7A],
            Vendor::Intel => [0x5A, 0x9C, 0xD8],
            Vendor::Tyan => [0x9C, 0xB8, 0x6A],
            Vendor::Inspur => [0x6A, 0xB8, 0xB0],
        }
    }
}

impl Family {
    /// The vendor a family implies when nothing says otherwise. Both AMI
    /// families are OEM firmware, so they imply only AMI until the probe reads
    /// the real brand.
    pub fn vendor(self) -> Vendor {
        match self {
            Family::Aten => Vendor::Supermicro,
            Family::Quanta => Vendor::Ami,
            Family::Ilo4 => Vendor::Hp,
            Family::Idrac9 | Family::Idrac8 => Vendor::Dell,
            Family::Spx => Vendor::Ami,
            Family::Avocent => Vendor::Gigabyte,
        }
    }

    /// Whether this family's firmware is sold under other brands, so the probe
    /// should read the real one: AMI's (both generations), and Insyde's, which
    /// Intel's S2600 boards run as well as Supermicro's.
    pub fn is_oem_firmware(self) -> bool {
        matches!(self, Family::Quanta | Family::Spx | Family::Aten)
    }
}

/// What to call a controller: the brand, then the firmware it runs.
pub fn controller_label(family: Family, vendor: Vendor) -> String {
    match (family, vendor) {
        (Family::Avocent, Vendor::Dell) => "Dell PowerEdge C / Avocent MergePoint".into(),
        (Family::Spx, Vendor::Ami) => "AMI MegaRAC SP-X".into(),
        (Family::Spx, v) => format!("{} / AMI SP-X", v.name()),
        (Family::Quanta, Vendor::Ami) => "AMI MegaRAC".into(),
        (Family::Quanta, v) => format!("{} / AMI MegaRAC", v.name()),
        (Family::Aten, Vendor::Supermicro) => Family::Aten.label().into(),
        (Family::Aten, v) => format!("{} / Insyde BMC", v.name()),
        (f, _) => f.label().into(),
    }
}

/// Detect a host's BMC family and who made it, with unauthenticated probes.
pub fn detect_vendor(host: &str) -> (Family, Vendor) {
    // Avocent first, for the reason in `detect`. Its login page names the
    // product, and the Dell build calls itself "Dell Remote Management
    // Controller".
    if let Some(info) = avocent::detect(host) {
        let vendor = if info.product.contains("Dell") { Vendor::Dell } else { Vendor::Gigabyte };
        return (Family::Avocent, vendor);
    }
    let family = detect_after_avocent(host);
    (family, family.vendor())
}

/// Detect a host's BMC family using unauthenticated vendor probes.
///
/// Avocent is probed first: its old Appweb server handles a burst of failed
/// TLS connections poorly, so running the other probes first can make it look
/// like the ATEN fallback.
pub fn detect(host: &str) -> Family {
    detect_vendor(host).0
}

fn detect_after_avocent(host: &str) -> Family {
    if idrac::detect(host).is_some() {
        return Family::Idrac9;
    }
    // iDRAC 8 lacks the 9's endpoint, and so fell through to the ATEN guess
    // before this probe existed.
    if idrac8::detect(host).is_some() {
        return Family::Idrac8;
    }
    if ilo4::detect(host).is_some() {
        return Family::Ilo4;
    }
    // The GoAhead MegaRAC generation has /rpc/WEBSES/create.asp and no
    // Redfish; SP-X is the reverse, so test the older stack first.
    if quanta::is_ami_megarac(host) {
        return Family::Quanta;
    }
    if spx::detect(host).is_some() {
        return Family::Spx;
    }
    Family::Aten
}

/// Whether this family's BMC can fetch an image URL itself, so `url` can be
/// mounted without proxying it. iLO and iDRAC both take a URL through Redfish,
/// as a CD only — so a disk image (`.img`) is always proxied.
pub fn native_url_media(family: Family, url: &str) -> bool {
    let img = crate::media_source::file_name(url).to_ascii_lowercase().ends_with(".img");
    matches!(family, Family::Ilo4 | Family::Idrac9) && !img
}

/// Hand `url` to the BMC to fetch, as its virtual CD. The returned mount
/// carries no data — the BMC talks to the URL's server, not to us — and
/// ejects the image when it is unmounted, since Redfish media outlives the
/// client that inserted it.
///
/// This is not the `mount-url` exception: the BMC connects to wherever the URL
/// points, never back to this machine.
pub fn mount_url_native(family: Family, host: &str, user: &str, pass: &str, url: &str)
    -> std::io::Result<crate::vmedia::Mount>
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    match family {
        Family::Ilo4 => ilo4::insert_media(host, user, pass, url, false)?,
        Family::Idrac9 => idrac::insert_media(host, user, pass, url)?,
        _ => return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "this BMC cannot mount a URL itself")),
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (s, h, u, p) = (stop.clone(), host.to_string(), user.to_string(), pass.to_string());
    let handle = std::thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // Unmounting is the user's doing (an eject, a disconnect), begun
        // now, though this thread was started with the mount.
        let _ = crate::net::deliberately(|| match family {
            Family::Ilo4 => ilo4::eject_media(&h, &u, &p),
            _ => idrac::eject_media(&h, &u, &p),
        });
    });
    Ok(crate::vmedia::Mount::from_parts(stop, handle, url.to_string(), 0,
                                        Arc::new(crate::vmedia::Stats::default())))
}

#[cfg(test)]
mod tests {
    use super::Family;

    #[test]
    fn persisted_keys_round_trip() {
        for family in Family::ALL {
            assert_eq!(Family::from_key(family.key()), Some(family));
        }
    }

    #[test]
    fn unknown_persisted_key_is_rejected() {
        assert_eq!(Family::from_key("unknown"), None);
    }
}
