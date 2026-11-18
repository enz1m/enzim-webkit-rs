//! Process-wide ownership of safe WPE entry points.

use std::sync::OnceLock;
use std::thread::ThreadId;

/// Native WPE initialization was attempted on an unsupported thread.
///
/// The owning thread is retained for the process lifetime, including after a
/// failed initialization or after every native object has been dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeThreadError;

impl core::fmt::Display for NativeThreadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WPE requires its owning thread; WPE 2.55 and newer also require the process main thread")
    }
}

impl std::error::Error for NativeThreadError {}

unsafe extern "C" {
    fn g_timeout_source_new(interval_ms: u32) -> *mut std::ffi::c_void;
    fn g_source_set_callback(
        source: *mut std::ffi::c_void,
        callback: unsafe extern "C" fn(*mut std::ffi::c_void) -> i32,
        data: *mut std::ffi::c_void,
        notify: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    );
    fn g_source_set_ready_time(source: *mut std::ffi::c_void, ready_time: i64);
    fn g_source_set_priority(source: *mut std::ffi::c_void, priority: i32);
    fn g_source_attach(source: *mut std::ffi::c_void, context: *mut std::ffi::c_void) -> u32;
    fn g_source_destroy(source: *mut std::ffi::c_void);
    fn g_source_unref(source: *mut std::ffi::c_void);
    fn g_get_monotonic_time() -> i64;
    fn g_main_context_default() -> *mut std::ffi::c_void;
    fn g_main_context_wakeup(context: *mut std::ffi::c_void);
    fn webkit_get_major_version() -> u32;
    fn webkit_get_minor_version() -> u32;
    fn enzui_wpe_is_process_main_thread() -> i32;
}

pub(crate) struct NativePumpDeadline {
    source: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
}

impl NativePumpDeadline {
    pub(crate) fn new(cap: std::time::Duration) -> Option<Self> {
        claim().ok()?;
        // SAFETY: GLib retains the default context; acquisition never waits for another owner.
        let context = unsafe { g_main_context_default() };
        // SAFETY: acquisition is paired with this guard's release on the native owner thread.
        if unsafe { g_main_context_acquire(context) } == 0 {
            return None;
        }
        let mut deadline = Self {
            source: std::ptr::null_mut(),
            context,
        };
        unsafe extern "C" fn elapsed(_: *mut std::ffi::c_void) -> i32 {
            0
        }
        // SAFETY: GLib creates an owned source; its callback has no borrowed data.
        let source = unsafe { g_timeout_source_new(0) };
        deadline.source = source;
        if source.is_null() {
            return None;
        }
        // SAFETY: the source is owned until the guard destroys it on this thread.
        let attached = unsafe {
            let now = g_get_monotonic_time();
            let micros = i64::try_from(cap.as_micros()).unwrap_or(i64::MAX);
            g_source_set_callback(source, elapsed, std::ptr::null_mut(), None);
            g_source_set_priority(source, -100);
            // Round past the microsecond clock precision before removing the one-shot source.
            g_source_set_ready_time(source, now.saturating_add(micros).saturating_add(1));
            g_source_attach(source, context)
        };
        if attached == 0 {
            return None;
        }
        static TRACE: OnceLock<bool> = OnceLock::new();
        if *TRACE.get_or_init(|| std::env::var_os("ENZUI_WPE_PUMP_TRACE").is_some_and(|v| v == "1"))
        {
            static BUDGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(64);
            if BUDGET
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |n| n.checked_sub(1),
                )
                .is_ok()
            {
                eprintln!("ENZUI_WPE_PUMP blocking deadline_ms={}", cap.as_millis());
            }
        }
        Some(deadline)
    }
}

impl Drop for NativePumpDeadline {
    fn drop(&mut self) {
        // SAFETY: this guard owns the source even after GLib removes its context reference.
        unsafe {
            if !self.source.is_null() {
                g_source_destroy(self.source);
                g_source_unref(self.source);
            }
            g_main_context_release(self.context);
        }
    }
}

/// Wake a host watching the default native context, without claiming its thread.
/// This may be called after submitting commands from another thread.
pub fn wake_native_event_loop() {
    // SAFETY: GLib permits waking the process-long default context from any thread.
    unsafe { g_main_context_wakeup(g_main_context_default()) };
}

/// Whether this native runtime requires initialization on the process main thread.
/// This version query does not initialize WPE or claim its owning thread.
pub fn native_requires_process_main_thread() -> bool {
    // SAFETY: WebKit's version accessors return compile-time constants without initialization.
    let (major, minor) = unsafe { (webkit_get_major_version(), webkit_get_minor_version()) };
    major > 2 || (major == 2 && minor >= 55)
}

pub(crate) fn claim() -> Result<(), NativeThreadError> {
    // SAFETY: the native predicate only compares the calling kernel thread and process IDs.
    if native_requires_process_main_thread() && unsafe { enzui_wpe_is_process_main_thread() } == 0 {
        return Err(NativeThreadError);
    }
    static OWNER: OnceLock<ThreadId> = OnceLock::new();
    let current = std::thread::current().id();
    if *OWNER.get_or_init(|| current) == current {
        Ok(())
    } else {
        Err(NativeThreadError)
    }
}

/// Dispatch ready native events on the owning thread without sleeping.
///
/// Processes at most 64 iterations or two milliseconds of callbacks per call,
/// so a host event loop can give its other sources a turn. Individual native
/// callbacks may themselves take longer. This claims WPE's owning thread.
///
/// # Errors
/// Refuses dispatch on another thread or a worker with WPE 2.55 and newer.
pub fn dispatch_pending_native_events() -> Result<usize, NativeThreadError> {
    claim()?;
    let started = std::time::Instant::now();
    let mut dispatched = 0;
    while dispatched < 64 && started.elapsed() < std::time::Duration::from_millis(2) {
        // SAFETY: claim establishes the native owner; the default context is iterated without waiting.
        if unsafe {
            super::wpe::g_main_context_iteration(core::ptr::null_mut(), super::wpe::G_FALSE)
        } == super::wpe::G_FALSE
        {
            break;
        }
        dispatched += 1;
    }
    Ok(dispatched)
}

/// Poll hints for the owning thread's next native dispatch.
///
/// Descriptor numbers remain owned by GLib and may become stale. Poll them only;
/// dispatch with [`dispatch_pending_native_events`] and query again after every
/// dispatch or host command. No native object crosses the thread boundary.
#[derive(Debug, Clone)]
pub struct NativeInterest {
    /// GLib-owned descriptors and their `poll(2)` event masks.
    pub descriptors: Vec<(std::os::fd::RawFd, i16)>,
    /// Maximum wait; `None` means no native deadline.
    pub timeout: Option<std::time::Duration>,
}

/// Why native polling hints could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInterestError {
    WrongThread(NativeThreadError),
    ContextBusy,
    SourceLimit,
}

impl core::fmt::Display for NativeInterestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongThread(error) => error.fmt(f),
            Self::ContextBusy => f.write_str("the native context is owned by another thread"),
            Self::SourceLimit => {
                f.write_str("native polling sources exceed the bounded query capacity")
            }
        }
    }
}
impl std::error::Error for NativeInterestError {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PollDescriptor {
    fd: std::ffi::c_int,
    events: u16,
    revents: u16,
}

unsafe extern "C" {
    fn g_poll(fds: *mut PollDescriptor, count: u32, timeout_ms: i32) -> i32;
    fn g_main_context_acquire(context: *mut std::ffi::c_void) -> i32;
    fn g_main_context_release(context: *mut std::ffi::c_void);
    fn g_main_context_prepare(context: *mut std::ffi::c_void, priority: *mut i32) -> i32;
    fn g_main_context_query(
        context: *mut std::ffi::c_void,
        priority: i32,
        timeout: *mut i32,
        fds: *mut PollDescriptor,
        count: i32,
    ) -> i32;
}

/// Query native descriptors and the earliest GLib timeout on the owner thread.
///
/// The hints do not consume readiness. A zero timeout requires another bounded
/// dispatch immediately. Requery after processing any application command.
///
/// # Errors
/// Refuses a different owner, a busy context, or more than 65,536 descriptors
/// or eight consecutive changes to the queried source inventory.
pub fn native_event_interest() -> Result<NativeInterest, NativeInterestError> {
    claim().map_err(NativeInterestError::WrongThread)?;
    // SAFETY: GLib retains the global default context for the process lifetime.
    let context = unsafe { g_main_context_default() };
    // SAFETY: the global default context is process-long; all queries require acquisition.
    if unsafe { g_main_context_acquire(context) } == 0 {
        return Err(NativeInterestError::ContextBusy);
    }
    struct Acquired(*mut std::ffi::c_void);
    impl Drop for Acquired {
        fn drop(&mut self) {
            // SAFETY: this guard pairs the successful acquisition on the same thread.
            unsafe { g_main_context_release(self.0) };
        }
    }
    let _acquired = Acquired(context);
    let mut priority = 0;
    // SAFETY: the context is acquired and priority is writable.
    let ready = unsafe { g_main_context_prepare(context, &mut priority) } != 0;
    let mut timeout = -1;
    let mut descriptors = Vec::<PollDescriptor>::new();
    let mut complete = false;
    for _ in 0..8 {
        // SAFETY: the acquired context writes at most len records to the live allocation.
        let count = unsafe {
            g_main_context_query(
                context,
                priority,
                &mut timeout,
                descriptors.as_mut_ptr(),
                descriptors.len() as i32,
            )
        };
        if !(0..=65_536).contains(&count) {
            return Err(NativeInterestError::SourceLimit);
        }
        if count as usize <= descriptors.len() {
            descriptors.truncate(count as usize);
            complete = true;
            break;
        }
        descriptors.resize(count as usize, PollDescriptor::default());
    }
    if !complete {
        return Err(NativeInterestError::SourceLimit);
    }
    Ok(NativeInterest {
        descriptors: descriptors
            .into_iter()
            .filter(|fd| fd.fd >= 0)
            .map(|fd| (fd.fd, fd.events as i16))
            .collect(),
        timeout: if ready {
            Some(std::time::Duration::ZERO)
        } else {
            u64::try_from(timeout)
                .ok()
                .map(std::time::Duration::from_millis)
        },
    })
}

pub(crate) fn wait_native_events(cap: std::time::Duration) -> Result<(), NativeInterestError> {
    let interest = native_event_interest()?;
    let wait = interest.timeout.map_or(cap, |timeout| timeout.min(cap));
    if wait.is_zero() {
        return Ok(());
    }
    let mut descriptors: Vec<_> = interest
        .descriptors
        .into_iter()
        .map(|(fd, events)| PollDescriptor {
            fd,
            events: events as u16,
            revents: 0,
        })
        .collect();
    let timeout_ms = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    static TRACE: OnceLock<bool> = OnceLock::new();
    if *TRACE.get_or_init(|| std::env::var_os("ENZUI_WPE_PUMP_TRACE").is_some_and(|v| v == "1")) {
        static BUDGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(64);
        if BUDGET
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_sub(1),
            )
            .is_ok()
        {
            eprintln!(
                "ENZUI_WPE_PUMP poll fds={} timeout_ms={timeout_ms}",
                descriptors.len()
            );
        }
    }
    // SAFETY: g_poll only polls descriptor numbers and writes this live array's revents;
    // GLib retains ownership, so concurrent closure does not create a Rust descriptor borrow.
    unsafe {
        g_poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as u32,
            timeout_ms,
        )
    };
    Ok(())
}
