//! Fail-closed GObject signal connection: a zero handler id is an error rather
//! than a silently unbound signal.
//!

#[cfg(not(test))]
use super::wpe as ffi;
use core::ffi::c_void;
use std::ffi::CString;

/// A production signal connection returned handler id `0`.
///
/// Carries the exact static signal name so the failure a host sees names the
/// signal that could not be installed, not a generic "binding failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignalBindError {
    /// The detailed-signal name whose `g_signal_connect_data` returned `0`.
    pub signal: &'static str,
}

impl core::fmt::Display for SignalBindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "GObject refused to connect the `{}` signal (handler id 0): the \
             signal is unknown or renamed on this WebKit, so no callback was \
             installed",
            self.signal
        )
    }
}

impl std::error::Error for SignalBindError {}

/// Accept a native GLib signal handler id only when registration succeeded.
pub(crate) fn require_nonzero(id: u64, signal: &'static str) -> Result<u64, SignalBindError> {
    if id == 0 {
        Err(SignalBindError { signal })
    } else {
        Ok(id)
    }
}

/// Connect a single signal, refusing a zero handler id.
///
/// # Safety
///
/// `instance` must be a live GObject that owns `signal`, `callback` must match
/// that signal's ABI, and `data` must outlive every callback firing.
pub(crate) unsafe fn connect_checked(
    instance: *mut c_void,
    signal: &'static str,
    callback: extern "C" fn(),
    data: *mut c_void,
) -> Result<u64, SignalBindError> {
    // SAFETY: forwarded to the caller's contract.
    let id = unsafe { raw_connect(instance, signal, callback, data) };
    if id == 0 {
        return Err(SignalBindError { signal });
    }
    Ok(id)
}

/// Accumulates the nonzero handler ids of a multi-signal binding so that a
/// later zero-id refusal can undo the partial binding.
///
/// Each id is tracked with the exact GObject instance it was connected to
/// (a policy binding spans two distinct instances - the `WebKitWebView` and
/// its `WebKitNetworkSession`), so rollback disconnects each id from the
/// correct object exactly once.
pub(crate) struct SignalBinder {
    connected: Vec<(*mut c_void, u64)>,
}

impl SignalBinder {
    pub(crate) fn new() -> Self {
        Self {
            connected: Vec::new(),
        }
    }

    /// Connect `signal` on `instance`, refusing a zero handler id.
    ///
    /// On refusal every earlier nonzero id is disconnected from its own
    /// instance exactly once and the accumulator is emptied, so the caller
    /// cannot go on to expose a binding that is missing a callback.
    ///
    /// # Safety
    ///
    /// Same contract as [`connect_checked`].
    pub(crate) unsafe fn connect(
        &mut self,
        instance: *mut c_void,
        signal: &'static str,
        callback: extern "C" fn(),
        data: *mut c_void,
    ) -> Result<u64, SignalBindError> {
        // SAFETY: forwarded to the caller's contract.
        let id = unsafe { raw_connect(instance, signal, callback, data) };
        if id == 0 {
            self.rollback();
            return Err(SignalBindError { signal });
        }
        self.connected.push((instance, id));
        Ok(id)
    }

    /// Disconnect every accumulated id from its own instance exactly once.
    fn rollback(&mut self) {
        for (instance, id) in self.connected.drain(..) {
            // SAFETY: each `id` was returned nonzero by `raw_connect` for
            // `instance` in this same binding and has not been disconnected.
            unsafe { disconnect(instance, id) };
        }
    }
}

/// Disconnect a nonzero handler from the GObject that owns it.
///
/// # Safety
///
/// `instance` must remain live and `id` must identify a connected handler on
/// that instance which has not already been disconnected.
pub(crate) unsafe fn disconnect(instance: *mut c_void, id: u64) {
    // SAFETY: forwarded to the caller's contract.
    unsafe { raw_disconnect(instance, id) };
}

// ---------------------------------------------------------------------------
// Production path: the real GObject FFI.
// ---------------------------------------------------------------------------

#[cfg(not(test))]
unsafe fn raw_connect(
    instance: *mut c_void,
    signal: &'static str,
    callback: extern "C" fn(),
    data: *mut c_void,
) -> u64 {
    let name = CString::new(signal).expect("static signal has no NUL");
    // SAFETY: the caller of `connect_checked` / `SignalBinder::connect`
    // guarantees `instance` owns `signal`, `callback` matches its ABI, and
    // `data` outlives every firing.
    unsafe {
        ffi::g_signal_connect_data(
            instance,
            name.as_ptr(),
            callback,
            data,
            core::ptr::null_mut(),
            0,
        )
    }
}

#[cfg(not(test))]
unsafe fn raw_disconnect(instance: *mut c_void, id: u64) {
    // SAFETY: `id` is a live nonzero handler id for `instance`.
    unsafe { ffi::g_signal_handler_disconnect(instance, id) };
}

// ---------------------------------------------------------------------------
// Test seam: no live GObject required.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod seam {
    use core::ffi::c_void;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    #[derive(Clone, Copy)]
    struct Registration {
        instance: *mut c_void,
        callback: extern "C" fn(),
        data: *mut c_void,
    }

    #[derive(Default)]
    pub(crate) struct SignalSeam {
        /// Signal names for which the next connect returns id 0.
        force_zero: HashSet<&'static str>,
        /// Monotonic source of fake nonzero ids.
        next_id: u64,
        active: HashSet<u64>,
        registrations: HashMap<u64, Registration>,
        /// Every handler id passed to disconnect, in order.
        pub disconnects: Vec<u64>,
    }

    thread_local! {
        pub(crate) static SEAM: RefCell<SignalSeam> = RefCell::new(SignalSeam::default());
    }

    /// Reset the seam and mark `zero_signals` to fail with a zero id.
    pub(crate) fn install(zero_signals: &[&'static str]) {
        SEAM.with(|s| {
            let mut s = s.borrow_mut();
            *s = SignalSeam::default();
            for name in zero_signals {
                s.force_zero.insert(name);
            }
        });
    }

    pub(crate) fn fail_next(zero_signals: &[&'static str]) {
        SEAM.with(|s| {
            let mut s = s.borrow_mut();
            for name in zero_signals {
                s.force_zero.insert(name);
            }
        });
    }

    pub(crate) fn connect(
        instance: *mut c_void,
        signal: &'static str,
        callback: extern "C" fn(),
        data: *mut c_void,
    ) -> u64 {
        SEAM.with(|s| {
            let mut s = s.borrow_mut();
            if s.force_zero.remove(signal) {
                0
            } else {
                s.next_id += 1;
                let id = s.next_id;
                s.active.insert(id);
                s.registrations.insert(
                    id,
                    Registration {
                        instance,
                        callback,
                        data,
                    },
                );
                id
            }
        })
    }

    pub(crate) fn disconnect(instance: *mut c_void, id: u64) {
        SEAM.with(|s| {
            let mut s = s.borrow_mut();
            if s.registrations
                .get(&id)
                .is_some_and(|registration| registration.instance == instance)
            {
                s.active.remove(&id);
                s.registrations.remove(&id);
            }
            s.disconnects.push(id);
        });
    }

    pub(crate) fn disconnects() -> Vec<u64> {
        SEAM.with(|s| s.borrow().disconnects.clone())
    }

    pub(crate) fn active_ids() -> Vec<u64> {
        SEAM.with(|s| {
            let mut ids: Vec<_> = s.borrow().active.iter().copied().collect();
            ids.sort_unstable();
            ids
        })
    }

    pub(crate) fn registration(id: u64) -> Option<(extern "C" fn(), *mut c_void)> {
        SEAM.with(|s| {
            s.borrow()
                .registrations
                .get(&id)
                .map(|registration| (registration.callback, registration.data))
        })
    }
}

#[cfg(test)]
unsafe fn raw_connect(
    instance: *mut c_void,
    signal: &'static str,
    callback: extern "C" fn(),
    data: *mut c_void,
) -> u64 {
    // Prove the signal name is a valid C string even on the test path, so a
    // NUL smuggled into a static name would still be caught.
    let _ = CString::new(signal).expect("static signal has no NUL");
    seam::connect(instance, signal, callback, data)
}

#[cfg(test)]
unsafe fn raw_disconnect(instance: *mut c_void, id: u64) {
    seam::disconnect(instance, id);
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn dummy() {}

    fn inst(n: usize) -> *mut c_void {
        n as *mut c_void
    }

    #[test]
    fn binder_refuses_failure_and_rolls_back_only_connected_handlers() {
        seam::install(&["decide-policy"]);
        let mut binder = SignalBinder::new();
        let err = unsafe { binder.connect(inst(1), "decide-policy", dummy, inst(9)) }.unwrap_err();
        assert_eq!(err.signal, "decide-policy");
        assert!(
            seam::disconnects().is_empty(),
            "no earlier id existed, so nothing is disconnected"
        );

        {
            // download-started is the last connect in a policy binding: forcing it
            // to zero must disconnect all four earlier view-handler ids, each once.
            seam::install(&["download-started"]);
            let mut binder = SignalBinder::new();
            let ids: Vec<u64> = ["decide-policy", "permission-request", "tls", "create"]
                .iter()
                .map(|sig| unsafe { binder.connect(inst(1), sig, dummy, inst(9)) }.unwrap())
                .collect();
            let err =
                unsafe { binder.connect(inst(2), "download-started", dummy, inst(9)) }.unwrap_err();
            assert_eq!(err.signal, "download-started");

            let mut disconnected = seam::disconnects();
            disconnected.sort_unstable();
            let mut expected = ids.clone();
            expected.sort_unstable();
            assert_eq!(
                disconnected, expected,
                "every earlier nonzero id must be disconnected exactly once"
            );
            assert_eq!(
                seam::disconnects().len(),
                ids.len(),
                "exactly once — no id disconnected twice, none skipped"
            );
        }
    }

    #[test]
    fn connect_checked_refuses_zero_for_each_single_handler_signal() {
        for signal in ["web-process-terminated", "load-changed"] {
            seam::install(&[signal]);
            let err = unsafe { connect_checked(inst(1), signal, dummy, inst(9)) }.unwrap_err();
            assert_eq!(err.signal, signal);
            assert!(
                seam::disconnects().is_empty(),
                "a single-handler refusal has no earlier id to disconnect"
            );
        }
    }
}
