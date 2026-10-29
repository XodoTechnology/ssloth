//! napi binding: embeds bmc-core inside ssloth's Node server.
//!
//! A `BmcSession` is one console on its own threads — the same front-end role
//! the egui and Tauri apps play, driven over napi. Frames leave as
//! `frame_pump` wire packets (decoded/painted browser-side by the ported
//! frames.ts); input enters as `input::Event`s through one `FamilyEncoder`
//! (which owns held-key/modifier/seq state per family); routes install into
//! `net`'s global table as a `Vec<Route>` chain dialled outermost-first.

use bmc_core::console::{self, Attempt};
use bmc_core::events::{Event, EventSink, Sink};
use bmc_core::frame_pump::{Format, FramePump};
use bmc_core::input::encoder::{Encode, FamilyEncoder};
use bmc_core::input::Event as InputEvent;
use bmc_core::jobs::Jobs;
use bmc_core::routes::{Auth, Kind, Route};
use bmc_core::{event_log, families, ipmi, media, net, power, vmedia};
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc, Mutex};

/// One hop of a bastion chain, mapped from a ssloth jump host record.
#[napi(object)]
pub struct RouteSpec {
    pub name: String,
    /// "ssh" or "socks5".
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// "agent" | "key" | "password"
    pub auth: String,
    pub key_file: Option<String>,
    /// Password or key passphrase.
    pub secret: Option<String>,
    /// Pinned SHA256: fingerprint; empty = trust on first use.
    pub host_key: Option<String>,
    /// Name of another hop to reach this one through (nested chains).
    pub via: Option<String>,
}

#[napi(object)]
pub struct SessionSpec {
    pub host: String,
    pub user: String,
    pub pass: String,
    /// Take the console from another user (iLO asks them).
    pub seize: Option<bool>,
}

/// Install a resolved bastion chain for one BMC address. Call before open.
#[napi]
pub fn set_route(addr: String, hops: Vec<RouteSpec>) -> Result<()> {
    let chain: Vec<Route> = hops
        .into_iter()
        .map(|h| Route {
            name: h.name,
            kind: if h.kind == "socks5" { Kind::Socks5 } else { Kind::Ssh },
            host: h.host,
            port: h.port,
            user: h.user,
            auth: match h.auth.as_str() {
                "key" => Auth::Key,
                "password" => Auth::Password,
                _ => Auth::Agent,
            },
            key_file: h.key_file.unwrap_or_default(),
            secret: h.secret.unwrap_or_default(),
            host_key: h.host_key.unwrap_or_default(),
            via: h.via.unwrap_or_default(),
        })
        .collect();
    net::set_route(&addr, Ok(chain));
    Ok(())
}

/// Clear any route so `addr` dials direct.
#[napi]
pub fn clear_route(addr: String) {
    net::set_route(&addr, Ok(vec![]));
}

struct JsSink {
    tsfn: ThreadsafeFunction<String>,
}

impl EventSink for JsSink {
    fn emit(&self, event: Event) {
        let s = match event {
            Event::ConnectFinished { host } => format!("connect_finished:{host}"),
            Event::SessionEnded { id, host } => format!("session_ended:{id}:{host}"),
            Event::Notice(m) => format!("notice:{m}"),
            Event::Problem(m) => format!("problem:{m}"),
            Event::MountChanged { host } => format!("mount_changed:{host}"),
        };
        self.tsfn.call(Ok(s), ThreadsafeFunctionCallMode::NonBlocking);
    }
}

/// Everything the connected console owns: the console itself (media mounts
/// borrow its session/token pieces), its family's input encoder, the teardown
/// a close must run, and live media mounts to detach on close.
struct ConsoleHandle {
    console: console::Console,
    enc: FamilyEncoder,
    closing: Option<console::Closing>,
    jobs: Jobs,
    sink: Sink,
    mounts: Vec<vmedia::Mount>,
}

#[napi]
pub struct BmcSession {
    cancel: Arc<AtomicBool>,
    /// Empty until the connect thread adopts the console; the JS side sees
    /// "ready" once this is filled.
    handle: Arc<Mutex<Option<ConsoleHandle>>>,
}

#[napi]
impl BmcSession {
    /// Begin connecting. `on_event` gets `"progress:…"`, `"ready:<title>:<family>"`,
    /// `"error:…"`, `"ended:…"`; `on_frame` gets wire packets (~20 fps cap).
    #[napi(constructor)]
    pub fn new(
        spec: SessionSpec,
        on_event: ThreadsafeFunction<String>,
        on_frame: ThreadsafeFunction<Buffer>,
    ) -> Result<Self> {
        let session = Self {
            cancel: Arc::new(AtomicBool::new(false)),
            handle: Arc::new(Mutex::new(None)),
        };
        let cancel = session.cancel.clone();
        let handle = session.handle.clone();
        std::thread::spawn(move || {
            let progress = Arc::new(Mutex::new(String::from("starting")));
            let watcher = {
                let progress = progress.clone();
                let ev = on_event.clone();
                let cancel = cancel.clone();
                std::thread::spawn(move || {
                    let mut last = String::new();
                    while !cancel.load(Ordering::Relaxed) {
                        let cur = progress.lock().unwrap().clone();
                        if cur != last {
                            ev.call(Ok(format!("progress:{cur}")), ThreadsafeFunctionCallMode::NonBlocking);
                            last = cur;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(120));
                    }
                })
            };
            let attempt = Attempt {
                host: spec.host.clone(),
                user: spec.user.clone(),
                pass: spec.pass.clone(),
                progress,
                seize: spec.seize.unwrap_or(false),
                known: None,
                cancel: cancel.clone(),
            };
            let sink = Arc::new(JsSink { tsfn: on_event.clone() });
            let result = catch_unwind(AssertUnwindSafe(|| {
                console::open(attempt, Jobs::default(), sink).recv()
            }));
            cancel.store(true, Ordering::Relaxed);
            let _ = watcher.join();
            match result {
                Ok(Ok(Ok(ok))) => {
                    let title = ok.title.clone();
                    let (c, closing) = console::adopt(ok, &spec.host, spec.user, spec.pass);
                    let family = c.family;
                    let enc = FamilyEncoder::new(family);
                    let alive = c.alive.clone();
                    let decoder = c.decoder.clone();
                    *handle.lock().unwrap() = Some(ConsoleHandle {
                        console: c,
                        enc,
                        closing: Some(closing),
                        jobs: Jobs::default(),
                        sink: Arc::new(JsSink { tsfn: on_event.clone() }) as Sink,
                        mounts: Vec::new(),
                    });
                    on_event.call(Ok(format!("ready:{title}:{family:?}")), ThreadsafeFunctionCallMode::NonBlocking);
                    let ev = on_event.clone();
                    std::thread::spawn(move || {
                        let mut pump = FramePump::new(decoder);
                        while alive.load(Ordering::Relaxed) {
                            if let Some(bytes) = pump.pull_wire(Format::Rgb5551) {
                                on_frame.call(Ok(bytes.into()), ThreadsafeFunctionCallMode::NonBlocking);
                            } else {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                        }
                        ev.call(Ok("ended".into()), ThreadsafeFunctionCallMode::NonBlocking);
                    });
                }
                Ok(Ok(Err(e))) => {
                    on_event.call(Ok(format!("error:{e}")), ThreadsafeFunctionCallMode::NonBlocking);
                }
                Ok(Err(_)) | Err(_) => {
                    on_event.call(Ok("error:connect failed".into()), ThreadsafeFunctionCallMode::NonBlocking);
                }
            }
        });
        Ok(session)
    }

    fn encode_send(&self, ev: InputEvent) -> Result<()> {
        let mut h = self.handle.lock().unwrap();
        let h = h.as_mut().ok_or_else(|| Error::from_reason("console not ready"))?;
        let mut out = Vec::new();
        h.enc.encode(&ev, &mut out);
        for pkt in out {
            let _ = h.console.tx.send(pkt);
        }
        Ok(())
    }

    /// Mount an ISO — a local path on the server, or an http(s) URL the BMC
    /// fetches where it can (iLO/iDRAC) and is proxied elsewhere. Resolves via
    /// media::attach per family; result string says how the image is served.
    #[napi]
    pub fn mount_media(&self, spec: String) -> AsyncTask<MountTask> {
        let rx = self
            .handle
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|h| media::attach(&h.console, spec, &h.jobs, h.sink.clone()));
        AsyncTask::new(MountTask { rx, handle: self.handle.clone() })
    }

    /// Detach every mount this session holds.
    #[napi]
    pub fn unmount_media(&self) -> Result<()> {
        let mut h = self.handle.lock().unwrap();
        let h = h.as_mut().ok_or_else(|| Error::from_reason("console not ready"))?;
        for m in h.mounts.drain(..) {
            let _ = m.unmount();
        }
        Ok(())
    }

    /// HID usage (page 0x07) down/up; `repeat` for OS auto-repeat.
    #[napi]
    pub fn send_key(&self, usage: u16, down: bool, repeat: Option<bool>) -> Result<()> {
        self.encode_send(InputEvent::Key { usage, down, repeat: repeat.unwrap_or(false) })
    }

    /// Pointer at fraction x,y of an fw×fh framebuffer; buttons bitmask;
    /// wheel ±1.
    #[napi]
    pub fn send_pointer(&self, x: f64, y: f64, fw: u32, fh: u32, buttons: u8, wheel: i8) -> Result<()> {
        self.encode_send(InputEvent::Pointer {
            x: x as f32,
            y: y as f32,
            fb: (fw as usize, fh as usize),
            buttons,
            wheel,
        })
    }

    /// Type one character as a US-layout keystroke (paste-as-keys).
    #[napi]
    pub fn send_char(&self, c: String) -> Result<()> {
        let c = c.chars().next().ok_or_else(|| Error::from_reason("empty char"))?;
        self.encode_send(InputEvent::Char(c))
    }

    /// Release every held key/button (on blur).
    #[napi]
    pub fn release_all(&self) -> Result<()> {
        self.encode_send(InputEvent::ReleaseAll)
    }

    /// Ctrl+Alt+Del in the family's own encoding.
    #[napi]
    pub fn send_cad(&self) -> Result<()> {
        self.encode_send(InputEvent::CtrlAltDel)
    }

    /// End the console; releases the BMC's session/media handles.
    #[napi]
    pub fn close(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        let mut guard = self.handle.lock().unwrap();
        if let Some(h) = guard.as_mut() {
            for m in h.mounts.drain(..) {
                let _ = m.unmount();
            }
            if let Some(closing) = h.closing.take() {
                let _ = catch_unwind(AssertUnwindSafe(|| console::close(closing)));
            }
        }
    }
}

impl Drop for BmcSession {
    fn drop(&mut self) {
        self.close();
    }
}

// ---- Host commands without a console: power / IPMI / SEL / sensors ----
// Blocking network calls, so each is an AsyncTask the JS side awaits.

fn family_from(s: &str) -> Option<families::Family> {
    Some(match s.to_ascii_lowercase().as_str() {
        "aten" => families::Family::Aten,
        "quanta" => families::Family::Quanta,
        "ilo4" => families::Family::Ilo4,
        "idrac9" => families::Family::Idrac9,
        "idrac8" => families::Family::Idrac8,
        "spx" => families::Family::Spx,
        "avocent" => families::Family::Avocent,
        _ => return None,
    })
}

/// action: "on" | "off" | "reset" | "soft" (IPMI adds "cycle").
/// family empty/unknown → unauthenticated detect before sending.
pub struct PowerTask {
    host: String,
    user: String,
    pass: String,
    family: Option<families::Family>,
    action: String,
}

#[napi]
impl Task for PowerTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let family = self
            .family
            .unwrap_or_else(|| families::detect(&self.host));
        let code = match self.action.as_str() {
            "off" => 0,
            "on" => 1,
            "reset" | "cycle" => 2,
            _ => 3,
        };
        Ok(power::send_power(family, &self.host, &self.user, &self.pass, code))
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

#[napi]
pub fn power_cmd(spec: SessionSpec, action: String, family: Option<String>) -> AsyncTask<PowerTask> {
    AsyncTask::new(PowerTask {
        host: spec.host,
        user: spec.user,
        pass: spec.pass,
        family: family.as_deref().and_then(family_from),
        action,
    })
}

/// Raw IPMI chassis control — works on every IPMI-capable family.
pub struct IpmiPowerTask {
    host: String,
    user: String,
    pass: String,
    action: String,
}

#[napi]
impl Task for IpmiPowerTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        ipmi::power(&self.host, &self.user, &self.pass, &self.action)
            .map_err(|e| Error::from_reason(e.to_string()))
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

#[napi]
pub fn ipmi_power(spec: SessionSpec, action: String) -> AsyncTask<IpmiPowerTask> {
    AsyncTask::new(IpmiPowerTask {
        host: spec.host,
        user: spec.user,
        pass: spec.pass,
        action,
    })
}

/// Cold-reset the management controller itself (host power untouched).
pub struct BmcResetTask {
    host: String,
    user: String,
    pass: String,
}

#[napi]
impl Task for BmcResetTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        Ok(power::reset_bmc(&self.host, &self.user, &self.pass))
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

#[napi]
pub fn bmc_reset(spec: SessionSpec) -> AsyncTask<BmcResetTask> {
    AsyncTask::new(BmcResetTask {
        host: spec.host,
        user: spec.user,
        pass: spec.pass,
    })
}

/// System event log over IPMI → JSON [{id,created,source,severity,message}].
pub struct SelTask {
    host: String,
    user: String,
    pass: String,
}

#[napi]
impl Task for SelTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        let log = event_log::ipmi(&self.host, &self.user, &self.pass)
            .map_err(Error::from_reason)?;
        let entries: Vec<_> = log
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id, "created": e.created, "source": e.source,
                    "severity": e.severity, "message": e.message,
                })
            })
            .collect();
        Ok(serde_json::json!({ "source": log.source, "warnings": log.warnings, "entries": entries }).to_string())
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

#[napi]
pub fn read_sel(spec: SessionSpec) -> AsyncTask<SelTask> {
    AsyncTask::new(SelTask {
        host: spec.host,
        user: spec.user,
        pass: spec.pass,
    })
}

/// Sensor readings over IPMI → JSON [{name,reading,units,status,thresholds}].
pub struct SensorsTask {
    host: String,
    user: String,
    pass: String,
}

#[napi]
impl Task for SensorsTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        let s = event_log::ipmi_sensors(&self.host, &self.user, &self.pass)
            .map_err(Error::from_reason)?;
        let entries: Vec<_> = s
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name, "reading": e.reading, "units": e.units,
                    "status": e.status, "thresholds": e.thresholds,
                })
            })
            .collect();
        Ok(serde_json::json!({ "source": s.source, "warnings": s.warnings, "entries": entries }).to_string())
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

#[napi]
pub fn read_sensors(spec: SessionSpec) -> AsyncTask<SensorsTask> {
    AsyncTask::new(SensorsTask {
        host: spec.host,
        user: spec.user,
        pass: spec.pass,
    })
}

/// Unauthenticated family detection (probes HTTP/ports; no login).
pub struct DetectTask {
    host: String,
}

#[napi]
impl Task for DetectTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        let (family, vendor) = families::detect_vendor(&self.host);
        Ok(format!("{family:?}:{vendor:?}"))
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

#[napi]
pub fn detect_family(host: String) -> AsyncTask<DetectTask> {
    AsyncTask::new(DetectTask { host })
}

/// Waits on media::attach's result and retains the Mount on success.
pub struct MountTask {
    rx: Option<std::sync::mpsc::Receiver<media::Attached>>,
    handle: Arc<Mutex<Option<ConsoleHandle>>>,
}

#[napi]
impl Task for MountTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        let rx = self
            .rx
            .take()
            .ok_or_else(|| Error::from_reason("a mount is already running (or console not ready)"))?;
        match rx.recv() {
            Ok(Ok((mount, note))) => {
                if let Some(h) = self.handle.lock().unwrap().as_mut() {
                    h.mounts.push(mount);
                }
                Ok(format!("mounted{note}"))
            }
            Ok(Err(e)) => Err(Error::from_reason(e.to_string())),
            Err(_) => Err(Error::from_reason("mount thread ended")),
        }
    }
    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}
