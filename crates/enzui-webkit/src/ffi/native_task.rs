//! Owner-thread asynchronous results with deadlines and bounded native admission.
//!
//! Dispatch the owning GLib context and poll each task. Timeout and cancellation
//! finish the host result immediately, while admission remains occupied until
//! the native callback arrives. Callbacks must always run their native finish
//! function before completing or discarding the callback token.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use super::wpe;

const MAX_INFLIGHT: usize = 8;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);
thread_local! {
    static INFLIGHT: Cell<usize> = const { Cell::new(0) };
}

/// A refused, cancelled, expired or failed native operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeTaskError {
    /// The host cancelled the operation.
    Cancelled,
    /// Completion did not arrive within the requested deadline.
    TimedOut,
    /// Native callbacks are still pending at the admission limit.
    Busy,
    /// A caller argument is outside the supported bounds.
    InvalidInput(&'static str),
    /// Native execution failed; the diagnostic is bounded to 2,048 input bytes.
    Native(String),
    /// Native work was requested off its owning thread.
    WrongThread,
}

impl std::fmt::Display for NativeTaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("native task cancelled"),
            Self::TimedOut => f.write_str("native task deadline expired"),
            Self::Busy => f.write_str("native task admission limit reached"),
            Self::InvalidInput(reason) => write!(f, "invalid native task input: {reason}"),
            Self::Native(message) => write!(f, "native task failed: {message}"),
            Self::WrongThread => f.write_str("native task requires the owning WPE thread"),
        }
    }
}
impl std::error::Error for NativeTaskError {}

struct Limit {
    active: Cell<usize>,
    maximum: usize,
}

/// Shared admission budget for related native operations.
///
/// Clones share their limit. An additional eight-operation owner-thread budget
/// applies across all limiters, including tasks whose host handles were dropped.
#[derive(Clone)]
pub struct NativeTaskLimiter(Rc<Limit>);

impl Default for NativeTaskLimiter {
    fn default() -> Self {
        Self::new(4)
    }
}

impl NativeTaskLimiter {
    /// Create a shared budget; the requested limit is clamped to one through eight.
    pub fn new(maximum: usize) -> Self {
        Self(Rc::new(Limit {
            active: Cell::new(0),
            maximum: maximum.clamp(1, MAX_INFLIGHT),
        }))
    }

    /// Count operations whose native callbacks have not yet released admission.
    pub fn inflight(&self) -> usize {
        self.0.active.get()
    }
}

struct Permit(Rc<Limit>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.set(self.0.active.get() - 1);
        let _ = INFLIGHT.try_with(|count| count.set(count.get() - 1));
    }
}

struct Cancellation(*mut c_void);
impl Drop for Cancellation {
    fn drop(&mut self) {
        // SAFETY: this owner-thread guard owns the constructor's GCancellable reference.
        unsafe { wpe::g_object_unref(self.0) };
    }
}
impl Cancellation {
    fn cancel(&self) {
        // SAFETY: this guard owns a live cancellable on the native owner thread.
        unsafe { wpe::g_cancellable_cancel(self.0) };
    }
}

struct State<T> {
    deadline: Instant,
    finished: bool,
    result: Option<Result<T, NativeTaskError>>,
}

fn expire<T>(state: &Rc<RefCell<State<T>>>, cancel: &Cancellation) {
    let expired = {
        let mut state = state.borrow_mut();
        if !state.finished && Instant::now() >= state.deadline {
            state.finished = true;
            state.result = Some(Err(NativeTaskError::TimedOut));
            true
        } else {
            false
        }
    };
    if expired {
        cancel.cancel();
    }
}

/// One asynchronous native result, confined to its construction thread.
///
/// Polling observes deadlines; dispatch the owner context to deliver callbacks.
/// Dropping an unfinished handle requests cancellation without freeing callback
/// userdata or releasing its native admission permit.
pub struct NativeTask<T> {
    state: Rc<RefCell<State<T>>>,
    cancellation: Rc<Cancellation>,
}

/// Callback-owned completion token for one [`NativeTask`].
///
/// Keep this token in heap userdata until the actual native callback. It retains
/// the native admission permit even after the task is cancelled, expires or drops.
pub struct NativeTaskCompletion<T> {
    state: Weak<RefCell<State<T>>>,
    cancellation: Rc<Cancellation>,
    _permit: Permit,
}

impl<T> NativeTask<T> {
    /// Reserve admission and construct the host handle and callback token.
    ///
    /// # Errors
    /// Returns [`NativeTaskError::Busy`] when callbacks still occupy the budget,
    /// an invalid-input error for a zero or greater-than-five-minute timeout, or
    /// [`NativeTaskError::WrongThread`] outside the native owner thread.
    pub fn start(
        limiter: &NativeTaskLimiter,
        timeout: Duration,
    ) -> Result<(Self, NativeTaskCompletion<T>), NativeTaskError> {
        super::threading::claim().map_err(|_| NativeTaskError::WrongThread)?;
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(NativeTaskError::InvalidInput(
                "timeout must be in (0, 300s]",
            ));
        }
        if limiter.0.active.get() >= limiter.0.maximum
            || INFLIGHT.with(|count| count.get() >= MAX_INFLIGHT)
        {
            return Err(NativeTaskError::Busy);
        }
        limiter.0.active.set(limiter.0.active.get() + 1);
        INFLIGHT.with(|count| count.set(count.get() + 1));
        // SAFETY: GCancellable construction transfers one owned reference.
        let cancellation = Rc::new(Cancellation(unsafe { wpe::g_cancellable_new() }));
        let state = Rc::new(RefCell::new(State {
            deadline: Instant::now() + timeout,
            finished: false,
            result: None,
        }));
        Ok((
            Self {
                state: state.clone(),
                cancellation: cancellation.clone(),
            },
            NativeTaskCompletion {
                state: Rc::downgrade(&state),
                cancellation,
                _permit: Permit(limiter.0.clone()),
            },
        ))
    }

    /// Whether completion, cancellation or the deadline has finished the host result.
    pub fn is_finished(&self) -> bool {
        expire(&self.state, &self.cancellation);
        self.state.borrow().finished
    }

    /// Take the result once; later calls return `None`, including after delivery.
    pub fn take_result(&self) -> Option<Result<T, NativeTaskError>> {
        expire(&self.state, &self.cancellation);
        self.state.borrow_mut().result.take()
    }

    /// Request cancellation; returns false when the host result was already terminal.
    pub fn cancel(&self) -> bool {
        expire(&self.state, &self.cancellation);
        {
            let mut state = self.state.borrow_mut();
            if state.finished {
                return false;
            }
            state.finished = true;
            state.result = Some(Err(NativeTaskError::Cancelled));
        }
        self.cancellation.cancel();
        true
    }
}

impl<T> Drop for NativeTask<T> {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl<T> NativeTaskCompletion<T> {
    /// Borrow the native cancellable until this callback token is consumed.
    pub(crate) fn cancellable(&self) -> *mut c_void {
        self.cancellation.0
    }

    /// Whether native cancellation was requested, including by timeout or handle drop.
    pub fn is_cancelled(&self) -> bool {
        // SAFETY: this callback token retains a live GCancellable reference.
        unsafe { g_cancellable_is_cancelled(self.cancellation.0) != 0 }
    }

    /// Whether a subsequent stage may start, checking the deadline even without polling.
    pub fn is_active(&self) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        expire(&state, &self.cancellation);
        let active = !state.borrow().finished;
        active && !self.is_cancelled()
    }

    /// Publish a native result unless cancellation, timeout or handle drop won.
    /// Native finish/cleanup must already have run when this method is called.
    pub fn complete(self, result: Result<T, NativeTaskError>) {
        if let Some(state) = self.state.upgrade() {
            expire(&state, &self.cancellation);
            let mut state = state.borrow_mut();
            if !state.finished {
                state.finished = true;
                state.result = Some(result);
            }
        }
    }
}

/// Consume an owned GError into a bounded, owner-thread native-task diagnostic.
///
/// # Safety
/// `error` must be non-null and own one live GError allocation from a finish call.
pub(crate) unsafe fn take_gerror(error: *mut wpe::GError) -> NativeTaskError {
    // SAFETY: the caller transfers one native error with a valid NUL-terminated message.
    let result = unsafe {
        if (*error).domain == g_io_error_quark() && (*error).code == 19 {
            NativeTaskError::Cancelled
        } else {
            let mut bytes = Vec::new();
            if !(*error).message.is_null() {
                for offset in 0..2048 {
                    let byte = (*error).message.add(offset).read() as u8;
                    if byte == 0 {
                        break;
                    }
                    bytes.push(byte);
                }
            }
            NativeTaskError::Native(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    // SAFETY: ownership of this error was transferred by the caller.
    unsafe { wpe::g_error_free(error) };
    result
}
unsafe extern "C" {
    fn g_io_error_quark() -> u32;
    fn g_cancellable_is_cancelled(cancellable: *mut c_void) -> i32;
}
