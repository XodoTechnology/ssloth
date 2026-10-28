//! The release notes behind the GUI's "What's new" page. `CHANGELOG.md` is
//! compiled in rather than fetched, so the page describes the binary that is
//! running, and needs no network or GitHub to show it.

use std::sync::OnceLock;

const SOURCE: &str = include_str!("../../../CHANGELOG.md");

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// A version bump without its notes would leave the page calling the previous
// release's notes current. Caught here, the build finds it rather than a user.
const _: () = assert!(
    has_heading(SOURCE.as_bytes(), VERSION.as_bytes()),
    "CHANGELOG.md has no \"## <version>\" heading for the version in Cargo.toml",
);

/// Whether some line is `## <version>`, alone or followed by a space.
const fn has_heading(src: &[u8], version: &[u8]) -> bool {
    let mut line = 0;
    while line < src.len() {
        let start = line + 3;
        if start + version.len() <= src.len()
            && src[line] == b'#' && src[line + 1] == b'#' && src[line + 2] == b' '
        {
            let mut i = 0;
            while i < version.len() && src[start + i] == version[i] {
                i += 1;
            }
            let end = start + version.len();
            if i == version.len()
                && (end == src.len() || matches!(src[end], b' ' | b'\n' | b'\r'))
            {
                return true;
            }
        }
        while line < src.len() && src[line] != b'\n' {
            line += 1;
        }
        line += 1;
    }
    false
}

pub struct Release {
    pub version: &'static str,
    pub date: &'static str,
    pub sections: Vec<Section>,
}

pub struct Section {
    /// "Added", "Changed", "Fixed"; empty for bullets that precede any heading.
    pub title: &'static str,
    /// One string per bullet, its wrapped lines joined. Backticks are left in
    /// for the page to set as code.
    pub items: Vec<String>,
}

/// Newest first, as the file lists them.
pub fn releases() -> &'static [Release] {
    static PARSED: OnceLock<Vec<Release>> = OnceLock::new();
    PARSED.get_or_init(|| parse(SOURCE))
}

/// Only the subset the file is written in: `##` releases, `###` sections,
/// `- ` bullets with indented continuation lines, and HTML comments, which are
/// skipped. Anything else is ignored rather than shown half-rendered.
fn parse(src: &'static str) -> Vec<Release> {
    let mut out: Vec<Release> = Vec::new();
    let mut in_comment = false;
    for line in src.lines() {
        if in_comment || line.trim_start().starts_with("<!--") {
            in_comment = !line.contains("-->");
            continue;
        }
        if let Some(rest) = line.strip_prefix("## ") {
            let (version, date) = rest.split_once(" — ")
                .or_else(|| rest.split_once(" - "))
                .unwrap_or((rest, ""));
            out.push(Release { version: version.trim(), date: date.trim(), sections: Vec::new() });
            continue;
        }
        let Some(release) = out.last_mut() else { continue };
        if let Some(title) = line.strip_prefix("### ") {
            release.sections.push(Section { title: title.trim(), items: Vec::new() });
        } else if let Some(item) = line.strip_prefix("- ") {
            if release.sections.is_empty() {
                release.sections.push(Section { title: "", items: Vec::new() });
            }
            release.sections.last_mut().unwrap().items.push(item.trim().to_string());
        } else if line.starts_with(' ') && !line.trim().is_empty() {
            if let Some(item) = release.sections.last_mut().and_then(|s| s.items.last_mut()) {
                item.push(' ');
                item.push_str(line.trim());
            }
        }
    }
    out
}
