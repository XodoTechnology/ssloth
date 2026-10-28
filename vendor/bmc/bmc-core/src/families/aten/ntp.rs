//! The BMC's NTP client, paused for a clock roll-back.
//!
//! A BMC that keeps NTP running pulls a rolled-back clock forward again within
//! seconds, past the client certificate's expiry, and the next TLS handshake
//! fails as if the roll-back had never happened. So while a roll-back is owed,
//! NTP is switched off through the web UI's own date/time page and switched
//! back on, with the settings it had, before the clock is restored.
//!
//! Ported from the X9 web UI's `config_datetime` page:
//!
//! ```text
//! POST /cgi/ipmi.cgi  GET_DATE_TIME.XML=(0,0)&time_stamp=…
//!   -> <IPMI><TIME><INFO NTP="1" NTP_SERVER_PRI="…" NTP_SERVER_2ND="…"
//!        TIME_ZONE="0" DST_EN="0" YEAR="2026" MONTH="10" DAY="17"
//!        HOUR="18" MIN="43" SEC="50"/></TIME></IPMI>
//! POST /cgi/op.cgi    op=config_date_time&timezone=&dst_en=&ntp=on|off
//!                     &ntp_server_pri=&ntp_server_2nd=&year=&month=&day=
//!                     &hour=&min=&sec=
//! ```
//!
//! Both need the session's CSRF token in a `CSRF_TOKEN` header; without it
//! the read is a 403 "Token Value is not matched". The save takes every field
//! at once, so the ones not being changed are sent back as read.

use crate::auth;
use serde::{Deserialize, Serialize};

/// The date/time page's settings, as read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub ntp: bool,
    pub server_pri: String,
    pub server_2nd: String,
    /// Seconds east of UTC, as the page's time-zone list values it.
    pub timezone: String,
    pub dst_en: String,
    /// The BMC's wall clock at the read, local time, as the page has it.
    #[serde(skip)]
    pub wall: Option<Wall>,
}

/// Year, month (1-12), day, hour, minute, second, as the page sends them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wall(pub [String; 6]);

impl Wall {
    /// `t` (seconds since the epoch, UTC) on the BMC's local clock.
    pub fn at(t: i64, s: &Settings) -> Wall {
        let tz: i64 = s.timezone.trim().parse().unwrap_or(0);
        let dst = if s.dst_en.trim() != "0" && !s.dst_en.trim().is_empty() { 3600 } else { 0 };
        let local = t + tz + dst;
        let (y, m, d) = crate::clock::civil(local.div_euclid(86400));
        let secs = local.rem_euclid(86400);
        Wall([y.to_string(), m.to_string(), d.to_string(),
              format!("{:02}", secs / 3600), format!("{:02}", secs / 60 % 60), format!("{:02}", secs % 60)])
    }
}

/// The `INFO` element of a `GET_DATE_TIME.XML` answer.
pub fn parse(xml: &str) -> Option<Settings> {
    let at = xml.find("<INFO")?;
    let tag = &xml[at..at + xml[at..].find('>')?];
    let attr = |name: &str| -> Option<String> {
        let key = format!(" {name}=\"");
        let v = &tag[tag.find(&key)? + key.len()..];
        Some(v[..v.find('"')?].to_string())
    };
    let wall = ["YEAR", "MONTH", "DAY", "HOUR", "MIN", "SEC"].map(|k| attr(k));
    Some(Settings {
        ntp: attr("NTP")? == "1",
        server_pri: attr("NTP_SERVER_PRI").unwrap_or_default(),
        server_2nd: attr("NTP_SERVER_2ND").unwrap_or_default(),
        timezone: attr("TIME_ZONE").unwrap_or_else(|| "0".into()),
        dst_en: attr("DST_EN").unwrap_or_else(|| "0".into()),
        wall: wall.iter().all(Option::is_some).then(|| Wall(wall.map(Option::unwrap_or_default))),
    })
}

/// The save request: `s` with NTP `on`, and the wall clock `wall`.
///
/// The page builds this by string concatenation, unencoded; the values are
/// percent-encoded here, which is the same for the host names and numbers
/// it carries and safe for anything else. Day and month go as the page's
/// `parseInt` leaves them, without leading zeros.
pub fn save_body(s: &Settings, on: bool, wall: &Wall) -> String {
    let int = |v: &str| v.trim().parse::<i64>().map(|n| n.to_string()).unwrap_or_else(|_| v.to_string());
    let [y, mo, d, h, mi, se] = &wall.0;
    format!("op=config_date_time&timezone={}&dst_en={}&ntp={}&ntp_server_pri={}\
&ntp_server_2nd={}&year={}&month={}&day={}&hour={}&min={}&sec={}",
            auth::enc(&s.timezone), auth::enc(&s.dst_en), if on { "on" } else { "off" },
            auth::enc(&s.server_pri), auth::enc(&s.server_2nd),
            int(y), int(mo), int(d), auth::enc(h), auth::enc(mi), auth::enc(se))
}

const PAGE: &str = "config_datetime";

/// Run `f` in a web session of its own, logged out afterwards whatever `f`
/// returns: these BMCs allow only a handful.
fn in_session<T>(host: &str, user: &str, pass: &str,
                 f: impl FnOnce(&str, Option<&str>) -> Result<T, String>) -> Result<T, String> {
    let sid = auth::login(host, user, pass).map_err(|e| format!("web login: {e}"))?;
    let token = auth::csrf_token_on(host, &sid, PAGE);
    let r = f(&sid, token.as_deref());
    auth::logout(host, &sid);
    r
}

fn read_in(host: &str, sid: &str, token: Option<&str>) -> Result<Settings, String> {
    let ts = crate::clock::our_now();
    let (head, body) = auth::post_form(host, sid, "/cgi/ipmi.cgi",
                                       &format!("GET_DATE_TIME.XML=(0,0)&time_stamp={ts}"), PAGE, token)
        .map_err(|e| e.to_string())?;
    parse(&body).ok_or_else(|| format!("unexpected answer to GET_DATE_TIME ({})",
                                      head.lines().next().unwrap_or("no answer")))
}

/// The BMC's date/time settings.
pub fn read(host: &str, user: &str, pass: &str) -> Result<Settings, String> {
    in_session(host, user, pass, |sid, token| read_in(host, sid, token))
}

/// Save `s` with NTP `on`, and read it back: the page answers 200 whether or
/// not the BMC took the change.
pub fn write(host: &str, user: &str, pass: &str, s: &Settings, on: bool, wall: &Wall)
    -> Result<(), String>
{
    in_session(host, user, pass, |sid, token| {
        let (head, _) = auth::post_form(host, sid, "/cgi/op.cgi", &save_body(s, on, wall), PAGE, token)
            .map_err(|e| e.to_string())?;
        if !head.starts_with("HTTP/1.1 200") {
            return Err(format!("saving the date/time settings: {}",
                               head.lines().next().unwrap_or("no answer")));
        }
        let now = read_in(host, sid, token)?;
        if now.ntp != on {
            return Err(format!("the BMC still has NTP {}", if now.ntp { "on" } else { "off" }));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The structure the X9 page reads, as its GetDateTimeResp walks it.
    const ANSWER: &str = "<?xml version=\"1.0\"?>  <IPMI>  <TIME>  <INFO NTP=\"1\" \
NTP_SERVER_PRI=\"ntp1.example.com\" NTP_SERVER_2ND=\"192.0.2.123\" TIME_ZONE=\"3600\" \
DST_EN=\"1\" YEAR=\"2026\" MONTH=\"10\" DAY=\"07\" HOUR=\"08\" MIN=\"05\" SEC=\"09\"/>  \
</TIME>  </IPMI>";

    fn settings() -> Settings { parse(ANSWER).unwrap() }

    #[test]
    fn the_answer_is_parsed_into_its_settings() {
        let s = settings();
        assert!(s.ntp);
        assert_eq!((s.server_pri.as_str(), s.server_2nd.as_str()), ("ntp1.example.com", "192.0.2.123"));
        assert_eq!((s.timezone.as_str(), s.dst_en.as_str()), ("3600", "1"));
        assert_eq!(s.wall, Some(Wall(["2026", "10", "07", "08", "05", "09"].map(String::from))));
        assert!(!parse(&ANSWER.replace("NTP=\"1\"", "NTP=\"0\"")).unwrap().ntp);
        assert_eq!(parse("Token Value is not matched."), None);
    }

    #[test]
    fn disabling_sends_everything_back_as_read_but_ntp() {
        let s = settings();
        assert_eq!(save_body(&s, false, s.wall.as_ref().unwrap()),
            "op=config_date_time&timezone=3600&dst_en=1&ntp=off&ntp_server_pri=ntp1.example.com\
&ntp_server_2nd=192.0.2.123&year=2026&month=10&day=7&hour=08&min=05&sec=09");
    }

    #[test]
    fn restoring_sends_the_saved_servers_and_the_time_now_in_the_bmcs_zone() {
        let s = settings();
        // 2026-10-17 23:30:00 UTC, an hour east and in summer time: 01:30 on the 18th.
        let wall = Wall::at(1_792_279_800, &s);
        assert_eq!(wall, Wall(["2026", "10", "18", "01", "30", "00"].map(String::from)));
        assert!(save_body(&s, true, &wall).contains("&ntp=on&ntp_server_pri=ntp1.example.com&"));
    }

    #[test]
    fn odd_characters_in_a_server_name_are_encoded() {
        let s = Settings { server_pri: "a b&c".into(), ..settings() };
        assert!(save_body(&s, true, s.wall.as_ref().unwrap()).contains("ntp_server_pri=a%20b%26c&"));
    }

    #[test]
    fn saved_settings_survive_the_journal() {
        let s = settings();
        let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(Settings { wall: None, ..s }, back);
    }
}
