//! Interrupt handling, so a headless mount detaches instead of leaking.
//!
//! BMC virtual-media sessions are a scarce resource — iDRAC allows exactly one,
//! and a client that dies without detaching holds it until the BMC times the
//! session out. `bmc-kvm mount` runs until interrupted, so Ctrl-C is the normal
//! way it ends and it has to unwind cleanly.
//!
//! The handler itself only sets a flag; the serving loop notices and does the
//! actual detach, since nothing else is safe to call from a signal handler.

use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
mod imp {
    use super::{Ordering, INTERRUPTED};

    extern "C" fn on_signal(_sig: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }

    pub fn install() {
        unsafe {
            libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{Ordering, INTERRUPTED};

    // The console control handler rather than the CRT's `signal`: it is the
    // only one that also fires for Ctrl-Break, for the console window being
    // closed, and at logoff and shutdown — all of which would otherwise drop a
    // mount without detaching it. Declared by hand so this stays dependency
    // free; `windows-sys` would be a large crate for two symbols.
    const CTRL_C_EVENT: u32 = 0;
    const CTRL_BREAK_EVENT: u32 = 1;
    const CTRL_CLOSE_EVENT: u32 = 2;
    const CTRL_LOGOFF_EVENT: u32 = 5;
    const CTRL_SHUTDOWN_EVENT: u32 = 6;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    unsafe extern "system" fn on_ctrl(event: u32) -> i32 {
        match event {
            CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT => {
                INTERRUPTED.store(true, Ordering::SeqCst);
                // Returning TRUE means "handled", which stops Windows killing
                // the process immediately. For the close/logoff/shutdown events
                // that only buys a few seconds before it is terminated anyway,
                // which is the whole budget the detach gets.
                1
            }
            _ => 0,
        }
    }

    pub fn install() {
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }
}

/// Catch interrupts. Returns the flag they set.
pub fn install() -> &'static AtomicBool {
    imp::install();
    &INTERRUPTED
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Run `body` once per `interval` until interrupted, then run `cleanup`.
/// Used by the headless mount commands, which otherwise never return.
pub fn serve_until_interrupted<F, C>(interval: std::time::Duration, mut body: F, cleanup: C)
where
    F: FnMut(),
    C: FnOnce(),
{
    install();
    while !interrupted() {
        // Sleep in slices so the signal is noticed promptly.
        let mut left = interval;
        let step = std::time::Duration::from_millis(200);
        while left > std::time::Duration::ZERO && !interrupted() {
            let d = step.min(left);
            std::thread::sleep(d);
            left -= d;
        }
        if interrupted() {
            break;
        }
        body();
    }
    eprintln!("\ninterrupted - detaching…");
    cleanup();
}
