//! Compare timer polling with descriptor-driven dispatch on the native owner.

#![allow(
    unsafe_code,
    reason = "the probe owns GLib callback data and raw poll records"
)]

use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::ffi::{
    dispatch_pending_native_events, native_event_interest, wake_native_event_loop,
};
use enzui_webkit::page::{PageEvent, ScriptWorld};
use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn g_timeout_add(
        interval: u32,
        function: unsafe extern "C" fn(*mut c_void) -> c_int,
        data: *mut c_void,
    ) -> u32;
    fn g_source_remove(id: u32) -> c_int;
}
unsafe extern "C" fn mark(data: *mut c_void) -> c_int {
    // SAFETY: the owner removes the source before the stack cell drops.
    unsafe { &*data.cast::<Cell<bool>>() }.set(true);
    0
}
fn wait_ready(cap: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let hints = native_event_interest()?;
    let mut descriptors = hints
        .descriptors
        .iter()
        .map(|&(fd, events)| libc::pollfd {
            fd,
            events,
            revents: 0,
        })
        .collect::<Vec<_>>();
    let timeout = hints
        .timeout
        .unwrap_or(cap)
        .min(cap)
        .as_millis()
        .min(i32::MAX as u128) as i32;
    // SAFETY: the live vector supplies count writable poll records; stale fd numbers are kernel poll inputs, not Rust borrows.
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(())
}

struct Timeout<'a> {
    id: u32,
    fired: &'a Cell<bool>,
}
impl Drop for Timeout<'_> {
    fn drop(&mut self) {
        if !self.fired.get() {
            // SAFETY: the uncompleted owner-thread source is retired before its borrowed cell drops.
            unsafe { g_source_remove(self.id) };
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let polling = std::env::args().any(|arg| arg == "--polling");
    let hints = native_event_interest()?;
    assert!(
        !hints.descriptors.is_empty(),
        "native context has no wake descriptor"
    );
    assert!(
        std::thread::spawn(|| matches!(
            native_event_interest(),
            Err(enzui_webkit::ffi::NativeInterestError::WrongThread(_))
        ))
        .join()
        .unwrap(),
        "native polling query accepted a foreign owner"
    );
    let thread = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(20));
        wake_native_event_loop();
    });
    let started = Instant::now();
    wait_ready(Duration::from_millis(500))?;
    let wake_ms = started.elapsed().as_secs_f64() * 1000.0;
    thread.join().unwrap();
    assert!(wake_ms < 400.0, "cross-thread native wake was lost");
    let display = HeadlessDisplay::new()?;
    let mut session = WebSession::new(&display)?;
    session.load_html(
        "<!doctype html><title>Readiness</title><body>ready</body>",
        "about:blank",
        5000,
    )?;
    session.pump(100);
    let mut observations = Vec::new();
    let mut turns = 0_u64;
    for interval in [3, 11, 19, 27, 7, 15, 23, 31] {
        let fired = Cell::new(false);
        // SAFETY: this source is completed or removed on the owner before fired drops.
        let id = unsafe { g_timeout_add(interval, mark, (&raw const fired).cast_mut().cast()) };
        assert_ne!(id, 0);
        let _source = Timeout { id, fired: &fired };
        let hints = native_event_interest()?;
        assert!(
            hints
                .timeout
                .is_some_and(|timeout| timeout <= Duration::from_millis(u64::from(interval))),
            "native deadline missing from interest: {hints:?}"
        );
        let started = Instant::now();
        while !fired.get() && started.elapsed() < Duration::from_secs(2) {
            if polling {
                std::thread::sleep(Duration::from_millis(50));
            } else {
                wait_ready(Duration::from_millis(500))?;
            }
            dispatch_pending_native_events()?;
            turns += 1;
        }
        if !fired.get() {
            return Err("native deadline did not dispatch".into());
        }
        observations.push(started.elapsed().as_secs_f64() * 1000.0 - f64::from(interval));
    }
    let id = session.evaluate_script(
        "document.body.textContent='updated';document.body.textContent",
        &ScriptWorld::Page,
    )?;
    let started = Instant::now();
    let mut script = false;
    while started.elapsed() < Duration::from_secs(2) && !script {
        if polling {
            std::thread::sleep(Duration::from_millis(50));
        } else {
            wait_ready(Duration::from_millis(500))?;
        }
        dispatch_pending_native_events()?;
        script = session.take_page_events().iter().any(|event|
            matches!(event, PageEvent::ScriptResult { id: found, result: Ok(value) } if *found == id && value.contains("updated")));
    }
    assert!(script, "native IPC did not reach its owner");
    let script_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "READINESS_RESULT {{\"polling\":{polling},\"deadline_lateness_ms\":{observations:?},\"dispatch_turns\":{turns},\"script_ms\":{script_ms},\"wake_ms\":{wake_ms}}}"
    );
    Ok(())
}
