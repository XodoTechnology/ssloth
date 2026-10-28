//! Attaching virtual media to an open console, as the `mount:<addr>` job.
//!
//! A URL goes to the BMC to fetch where it can (iLO, iDRAC) and is otherwise
//! proxied, fetched here and served like a file — as is a URL the BMC refuses.
//! Every other path is the family's push-mode mount: we open the connection,
//! so no inbound route back to this machine is needed.

use crate::console::Console;
use crate::events::{Event, Sink};
use crate::families::Family;
use crate::jobs::{JobKey, Jobs};
use crate::vmedia;
use std::sync::mpsc::Receiver;

/// A mount's result: the mount, and a note on how the image is served.
pub type Attached = std::io::Result<(vmedia::Mount, &'static str)>;

/// Start attaching `spec` — a local image or an http(s) URL — to the
/// console's BMC on a thread; the receiver carries the result, and
/// `MountChanged` says when. None when a mount on that BMC is still running.
pub fn attach(s: &Console, spec: String, jobs: &Jobs, sink: Sink) -> Option<Receiver<Attached>> {
    use crate::families::{avocent, idrac, ilo4, quanta};
    let guard = jobs.begin(JobKey::Mount(s.host.clone()),
                           format!("Mounting {} on {}", crate::media_source::file_name(&spec), s.host))?;
    let (family, host, user, pass, token) =
        (s.family, s.host.clone(), s.user.clone(), s.pass.clone(), s.kvm_token.clone());
    let idrac_parts = s.idrac.as_ref().map(|is| {
        (is.launch.port, is.web.cookie.clone(), is.launch.vcsid.clone(), is.key2.clone())
    });
    let avocent_sess = s.avocent.clone();
    let spx_sess = s.spx.clone();
    let console = s.tx.clone();
    let (tx, rx) = std::sync::mpsc::channel();

    // Mounting is the user's own action, as a connect is.
    std::thread::spawn(move || crate::net::deliberately(|| {
        let _guard = guard;
        let err = |m: &str| std::io::Error::new(std::io::ErrorKind::Other, m.to_string());
        let mut note = "";
        let mut native = None;
        if crate::media_source::is_url(&spec) {
            if crate::families::native_url_media(family, &spec) {
                match crate::families::mount_url_native(family, &host, &user, &pass, &spec) {
                    Ok(m) => native = Some(m),
                    Err(_) => note = " (the BMC refused the URL, so it is proxied)",
                }
            } else {
                note = " (proxied through this machine)";
            }
        }
        let res = match native {
            Some(m) => Ok((m, " (fetched by the BMC)")),
            None => match family {
                // Quanta IUSB CD-ROM on :5120, then signal the host to attach.
                Family::Quanta => quanta::vmedia::mount(&host, quanta::vmedia::CD_PORT, &token, 0, &spec)
                    .inspect(|_| { let _ = console.send(quanta::kvm::media_state_packet(true)); }),
                Family::Ilo4 => ilo4::vmedia::mount(&host, &token, &spec),
                // iDRAC direct mode: the console session is already up, so its
                // rotated ticket lets us open the media channel outbound.
                Family::Idrac9 => match &idrac_parts {
                    Some((port, cookie, vcsid, key2)) => {
                        let key2 = key2.lock().unwrap().clone();
                        idrac::vmedia::mount(&host, *port, cookie, vcsid, &key2, &spec)
                    }
                    None => Err(err("no iDRAC session")),
                },
                // SP-X: the Java client's media tunnel through 443, on the
                // console's own web session and KVM token.
                Family::Spx => match &spx_sess {
                    Some(sess) => crate::families::spx::vmedia::mount(&host, &sess.cookie, &token, &spec),
                    None => Err(err("no SP-X web session")),
                },
                // Avocent AVMP: a third channel on the console port. The
                // credentials are minted per mount and only valid while the
                // console's own web session is logged in — which it is, because
                // the console thread holds it for the life of the console.
                Family::Avocent => match &avocent_sess {
                    Some(sess) => avocent::vm_launch(&host, sess)
                        .and_then(|launch| avocent::vmedia::mount(&host, &launch, &spec)),
                    None => Err(err("no Avocent web session")),
                },
                // The same AVMP behind Dell's web login, minted the same way.
                Family::Idrac8 => match &avocent_sess {
                    Some(sess) => crate::families::idrac8::vm_launch(&host, sess)
                        .and_then(|launch| avocent::vmedia::mount(&host, &launch, &spec)),
                    None => Err(err("no iDRAC web session")),
                },
                Family::Aten => vmedia::mount(&host, 623, &user, &pass, &spec, &|_| {}),
            }
            .map(|m| (m, note)),
        };
        // The session may have gone while we worked; nobody will eject a mount
        // that cannot be delivered, so do it here rather than leave it serving.
        if let Err(std::sync::mpsc::SendError(Ok((m, _)))) = tx.send(res) {
            if let Some(p) = m.unmount() {
                eprintln!("{p}");
            }
        }
        sink.emit(Event::MountChanged { host });
    }));
    Some(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::{adopt, ConnectOk, FamilyLink};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_mount_while_one_is_attaching_is_refused() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let (net, rtt, frame) = crate::console::trackers();
        let ok = ConnectOk {
            decoder: Arc::new(Mutex::new(crate::ast2100::Decoder::new(8, 8))),
            link: FamilyLink::new(tx, Arc::new(AtomicBool::new(true))),
            title: "fake".into(), family: Family::Aten, kvm_token: String::new(),
            notice: Default::default(), takeover: Default::default(), ended: Default::default(),
            idrac: None, avocent: None, spx: None, net, rtt, frame,
        };
        let (console, _closing) = adopt(ok, "192.0.2.6", "admin".into(), "secret".into());
        let jobs = Jobs::default();
        let _held = jobs.begin(JobKey::Mount("192.0.2.6".into()), "mounting").unwrap();
        assert!(attach(&console, "/nonexistent.iso".into(), &jobs, Arc::new(crate::events::Discard)).is_none());
    }
}
