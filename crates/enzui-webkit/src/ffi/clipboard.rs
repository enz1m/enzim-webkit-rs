//! The host clipboard, bridged to the real WPE `WPEClipboard`.
//!
//! A web page's copy writes to the display's clipboard; a paste reads from it.
//! This is the host-side seam a widget uses to move text between the page and
//! the rest of the desktop. What a headless test can observe honestly is
//! the round-trip through the real `WPEClipboard` object: set text → the
//! change-count advances → read the same text back. What it cannot observe is a
//! page's JS `navigator.clipboard` call reaching here (that needs a rendered
//! interactive page and a permission grant) - so this module gates the plumbing
//! that is real; widget/JavaScript routing is implemented above this layer.

use super::wpe;
use core::ffi::c_void;
use std::ffi::CString;
use std::ptr;

use crate::clipboard_bound;
use crate::ffi::runtime::HeadlessDisplay;

/// The UTF-8 plain-text clipboard format WebKit uses.
const TEXT_FORMAT: &str = "text/plain;charset=utf-8";

/// Re-export the ceiling so callers importing from [`ffi`](crate::ffi) find it.
pub use crate::clipboard_bound::MAX_CLIPBOARD_TEXT_BYTES;

/// Something went wrong bridging to the WPE clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    /// The display exposes no clipboard (`wpe_display_get_clipboard` was NULL).
    NoClipboard,
    /// A content bundle could not be allocated.
    ContentAllocFailed,
    /// The text held a NUL byte and cannot cross the C boundary.
    InteriorNul,
    /// GLib refused the clipboard change signal registration.
    SignalConnectFailed {
        /// Fixed operation context for diagnostics.
        context: &'static str,
    },
    /// The native clipboard returned text exceeding
    /// [`MAX_CLIPBOARD_TEXT_BYTES`].
    TextTooLarge {
        /// Reported native size in bytes.
        size: usize,
    },
}

impl From<clipboard_bound::ClipboardReadError> for ClipboardError {
    fn from(e: clipboard_bound::ClipboardReadError) -> Self {
        match e {
            clipboard_bound::ClipboardReadError::TextTooLarge { size } => {
                ClipboardError::TextTooLarge { size }
            }
        }
    }
}

impl std::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClipboardError::NoClipboard => write!(f, "display exposes no clipboard"),
            ClipboardError::ContentAllocFailed => write!(f, "clipboard content alloc failed"),
            ClipboardError::InteriorNul => write!(f, "clipboard text contains a NUL byte"),
            ClipboardError::SignalConnectFailed { context } => {
                write!(f, "native clipboard signal registration refused: {context}")
            }
            ClipboardError::TextTooLarge { size } => write!(
                f,
                "clipboard text too large ({size} bytes, limit {})",
                clipboard_bound::MAX_CLIPBOARD_TEXT_BYTES,
            ),
        }
    }
}

impl std::error::Error for ClipboardError {}

/// A borrowed handle to a display's clipboard.
///
/// The native clipboard is owned by the [`HeadlessDisplay`] and this handle
/// cannot outlive that display. The fixture below builds the handle inside a
/// nested scope and lets it escape, so the display is dropped while the handle
/// still borrows it. It does not compile:
///
/// ```compile_fail
/// use enzui_webkit::ffi::Clipboard;
/// use enzui_webkit::ffi::runtime::HeadlessDisplay;
///
/// let clipboard = {
///     let display = HeadlessDisplay::new().expect("headless display");
///     // The display dies at the end of this block; the handle borrows it.
///     Clipboard::for_display(&display).expect("display clipboard")
/// };
/// let _change_count = clipboard.change_count();
/// ```
///
/// That fixture writes `Clipboard` plainly, with no lifetime argument, exactly
/// as it would be written against a handle carrying no display borrow at all.
/// Deleting the borrow from this type therefore makes the fixture *compile*
/// and the `compile_fail` block go red, so the example measures the borrow
/// rule rather than its own syntax. `rustdoc` records only that compilation
/// failed, never which diagnostic fired, so no error code is claimed here: the
/// guarantee asserted is that this escape cannot be written in safe Rust. The
/// positive control shares the constructor and the safe method, so renaming or
/// removing either reddens the control instead of quietly satisfying the
/// compile-fail block. Same scope, same calls - this compiles:
///
/// ```no_run
/// use enzui_webkit::ffi::Clipboard;
/// use enzui_webkit::ffi::runtime::HeadlessDisplay;
///
/// let display = HeadlessDisplay::new().expect("headless display");
/// let clipboard = Clipboard::for_display(&display).expect("display clipboard");
/// let _change_count = clipboard.change_count();
/// ```
///
/// # Thread affinity
///
/// WPE binds the clipboard to the display's single thread, exactly like the
/// runtime, so the handle is `!Send + !Sync` - asserted by compilation, not
/// only by this sentence:
///
/// ```compile_fail
/// use enzui_webkit::ffi::Clipboard;
/// use enzui_webkit::ffi::runtime::HeadlessDisplay;
///
/// fn require_send<T: Send>(_: T) {}
///
/// let display = HeadlessDisplay::new().expect("headless display");
/// let clipboard = Clipboard::for_display(&display).expect("display clipboard");
/// require_send(clipboard);
/// ```
///
/// ```compile_fail
/// use enzui_webkit::ffi::Clipboard;
/// use enzui_webkit::ffi::runtime::HeadlessDisplay;
///
/// fn require_sync<T: Sync>(_: &T) {}
///
/// let display = HeadlessDisplay::new().expect("headless display");
/// let clipboard = Clipboard::for_display(&display).expect("display clipboard");
/// require_sync(&clipboard);
/// ```
///
/// Both bounds are refused structurally - the raw `WPEClipboard` pointer and
/// the borrow of the thread-affine display are each `!Send` and `!Sync`, and
/// `_not_send_sync` keeps that true even if the pointer field were ever
/// replaced by a thread-safe one. The control below proves those two helpers
/// accept an ordinary `Send + Sync` value, so the blocks above cannot pass
/// merely because the bound is unsatisfiable for everything:
///
/// ```
/// fn require_send<T: Send>(_: T) {}
/// fn require_sync<T: Sync>(_: &T) {}
///
/// let host_text = String::from("host text");
/// require_sync(&host_text);
/// require_send(host_text);
/// ```
pub struct Clipboard<'display> {
    // Borrowed from the display - never unref'd. This marker makes that native
    // ownership contract part of the safe Rust type without storing a second
    // runtime pointer or changing native reference counts.
    ptr: *mut wpe::WPEClipboard,
    _display: core::marker::PhantomData<&'display HeadlessDisplay>,
    _not_send_sync: core::marker::PhantomData<*const ()>,
}

impl<'display> Clipboard<'display> {
    /// Borrow `display`'s clipboard. `Err(NoClipboard)` if it has none.
    pub fn for_display(
        display: &'display HeadlessDisplay,
    ) -> Result<Clipboard<'display>, ClipboardError> {
        // SAFETY: `display.as_ptr()` is a live WPEDisplay*; the returned
        // clipboard is borrowed (owned by the display), and `_display` prevents
        // the safe handle from outliving that borrow.
        let ptr = unsafe { wpe::wpe_display_get_clipboard(display.as_ptr()) };
        if ptr.is_null() {
            return Err(ClipboardError::NoClipboard);
        }
        Ok(Clipboard {
            ptr,
            _display: core::marker::PhantomData,
            _not_send_sync: core::marker::PhantomData,
        })
    }

    /// The clipboard's change count - a monotone counter bumped on every write.
    /// A widget watches this to notice the page (or another app) copied.
    #[must_use]
    pub fn change_count(&self) -> i64 {
        // SAFETY: `self.ptr` is a live borrowed WPEClipboard*.
        unsafe { wpe::wpe_clipboard_get_change_count(self.ptr) }
    }

    /// Publish `text` as the clipboard's `text/plain;charset=utf-8` content.
    /// This is what a page's copy ultimately drives.
    pub fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        let c_text = CString::new(text).map_err(|_| ClipboardError::InteriorNul)?;
        // SAFETY: fresh content bundle rc=1.
        let content = unsafe { wpe::wpe_clipboard_content_new() };
        if content.is_null() {
            return Err(ClipboardError::ContentAllocFailed);
        }
        // SAFETY: `content` live; text copied by WPE.
        unsafe { wpe::wpe_clipboard_content_set_text(content, c_text.as_ptr()) };
        // SAFETY: `self.ptr` live; clipboard takes its own ref on `content`.
        unsafe { wpe::wpe_clipboard_set_content(self.ptr, content) };
        // SAFETY: drop the reference; the clipboard kept its own.
        unsafe { wpe::wpe_clipboard_content_unref(content) };
        Ok(())
    }

    /// Read the clipboard's plain text, if any. Returns
    /// [`Err(TextTooLarge)`](ClipboardError::TextTooLarge) when the native
    /// layer reports a size exceeding [`MAX_CLIPBOARD_TEXT_BYTES`], ensuring
    /// no unbounded allocation. The native pointer is freed on every non-null
    /// path.
    pub fn read_text(&self) -> Result<Option<String>, ClipboardError> {
        let fmt = CString::new(TEXT_FORMAT).expect("static, no NUL");
        let mut size: usize = 0;
        // SAFETY: `self.ptr` live; returns a g_malloc'd C string or NULL.
        let raw = unsafe { wpe::wpe_clipboard_read_text(self.ptr, fmt.as_ptr(), &mut size) };
        // SAFETY: `raw` is NULL or a `g_malloc`'d allocation whose first
        // `size` bytes are the clipboard text (WPE's `size` out-parameter
        // excludes the NUL terminator). `native_free` wraps `g_free`,
        // matching the `g_malloc` allocator. Ownership transfers in; the
        // pointer is freed exactly once on every non-null path.
        Ok(unsafe { clipboard_bound::convert_native_text(raw, size, native_free) }?)
    }
}

// ---------------------------------------------------------------------------
// Waiting for a clipboard change WITHOUT polling.
// ---------------------------------------------------------------------------

/// Shared with the `changed` handler and the deadline source.
struct ChangeWait {
    main_loop: *mut wpe::GMainLoop,
    changed: bool,
    deadline_fired: bool,
    #[cfg(test)]
    drop_probe: Option<std::rc::Rc<std::cell::Cell<usize>>>,
}

#[cfg(test)]
impl Drop for ChangeWait {
    fn drop(&mut self) {
        if let Some(probe) = &self.drop_probe {
            probe.set(probe.get() + 1);
        }
    }
}

/// `notify::change-count` handler: `void (GObject*, GParamSpec*, gpointer)`.
///
/// `WPEClipboardClass::changed` is a class vfunc, not a signal (connecting
/// to it yields `signal 'changed' is invalid for instance`), so the observable
/// event is the `change-count` property notification instead. Declared in
/// `/usr/share/gir-1.0/WPEPlatform-2.0.gir` as a readable property of
/// `WPEClipboard`.
extern "C" fn on_clipboard_changed(
    _clipboard: *mut wpe::WPEClipboard,
    _pspec: *mut c_void,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the live box owned by `wait_for_change`, which
    // disconnects this handler before dropping it.
    let state = unsafe { &mut *(user_data.cast::<ChangeWait>()) };
    state.changed = true;
    // SAFETY: the loop is alive until `wait_for_change` returns; quit is
    // idempotent so racing the deadline is harmless.
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
}

fn mark_change_deadline(state: &mut ChangeWait) -> wpe::GBoolean {
    state.deadline_fired = true;
    wpe::G_FALSE // G_SOURCE_REMOVE: one-shot.
}

extern "C" fn on_change_deadline(user_data: *mut c_void) -> wpe::GBoolean {
    // SAFETY: as above.
    let state = unsafe { &mut *(user_data.cast::<ChangeWait>()) };
    let disposition = mark_change_deadline(state);
    // SAFETY: idempotent quit.
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
    disposition
}

unsafe extern "C" {
    /// `void g_signal_handler_disconnect (gpointer instance, gulong handler_id);`
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gsignal.h`
    fn g_signal_handler_disconnect(instance: *mut c_void, handler_id: u64);
}

const CHANGE_SIGNAL: &str = "notify::change-count";

/// Operations whose ordering owns the callback-state lifetime. Keeping this
/// seam below `Clipboard` lets the refusal and both completion paths prove the
/// same production cleanup protocol without constructing a native object.
trait ChangeWaitBackend {
    fn connect(&mut self, state: *mut ChangeWait) -> u64;
    fn arm_timeout(&mut self, deadline_ms: u32, state: *mut ChangeWait) -> u32;
    fn run(&mut self, state: *mut ChangeWait);
    fn disconnect(&mut self, handler: u64);
    fn remove_timeout(&mut self, source: u32);
}

struct NativeChangeWait {
    clipboard: *mut wpe::WPEClipboard,
    main_loop: *mut wpe::GMainLoop,
}

impl ChangeWaitBackend for NativeChangeWait {
    fn connect(&mut self, state: *mut ChangeWait) -> u64 {
        let signal = CString::new("notify::change-count").expect("static, no NUL");
        // SAFETY: the callback matches the `notify` signature; GObject casts
        // it to GCallback, the clipboard is live, and `state` remains live
        // until this handler is disconnected.
        let cb: extern "C" fn() = unsafe {
            core::mem::transmute::<
                extern "C" fn(*mut wpe::WPEClipboard, *mut c_void, *mut c_void),
                extern "C" fn(),
            >(on_clipboard_changed)
        };
        // SAFETY: upheld above.
        unsafe {
            wpe::g_signal_connect_data(
                self.clipboard.cast::<c_void>(),
                signal.as_ptr(),
                cb,
                state.cast::<c_void>(),
                ptr::null_mut(),
                0,
            )
        }
    }

    fn arm_timeout(&mut self, deadline_ms: u32, state: *mut ChangeWait) -> u32 {
        // SAFETY: `on_change_deadline` is a GSourceFunc and state remains live
        // until the source fires or is removed.
        unsafe { wpe::g_timeout_add(deadline_ms, on_change_deadline, state.cast::<c_void>()) }
    }

    fn run(&mut self, _state: *mut ChangeWait) {
        // SAFETY: a timeout has been armed, so the loop always quits.
        unsafe { wpe::g_main_loop_run(self.main_loop) };
    }

    fn disconnect(&mut self, handler: u64) {
        // SAFETY: checked non-zero id returned for this live clipboard.
        unsafe { g_signal_handler_disconnect(self.clipboard.cast::<c_void>(), handler) };
    }

    fn remove_timeout(&mut self, source: u32) {
        // SAFETY: live source id created by `arm_timeout` and not yet fired.
        unsafe { wpe::g_source_remove(source) };
    }
}

fn run_change_wait<B: ChangeWaitBackend>(
    backend: &mut B,
    deadline_ms: u32,
    state: ChangeWait,
) -> Result<bool, ClipboardError> {
    let state = Box::into_raw(Box::new(state));
    struct StateGuard(*mut ChangeWait);
    impl Drop for StateGuard {
        fn drop(&mut self) {
            // SAFETY: every callback/source is disconnected or removed before
            // successful return. On connect refusal neither was installed.
            let _ = unsafe { Box::from_raw(self.0) };
        }
    }
    let _state_guard = StateGuard(state);

    // Connect first. A refused/renamed signal therefore cannot leave a timeout
    // holding the state pointer when this typed error drops the state.
    let handler =
        super::signal::require_nonzero(backend.connect(state), CHANGE_SIGNAL).map_err(|error| {
            ClipboardError::SignalConnectFailed {
                context: error.signal,
            }
        })?;

    // Only a checked live handler may be followed by a source borrowing state.
    let deadline_id = backend.arm_timeout(deadline_ms, state);
    backend.run(state);
    backend.disconnect(handler);

    // A fired timeout removes itself by returning G_SOURCE_REMOVE. The success
    // path removes the still-live source explicitly; either way exactly one
    // owner retires it before the state is read and dropped.
    let deadline_fired = unsafe { (*state).deadline_fired };
    if !deadline_fired {
        backend.remove_timeout(deadline_id);
    }
    Ok(unsafe { (*state).changed })
}

impl Clipboard<'_> {
    /// Block on the default main context until the clipboard's
    /// `notify::change-count` signal fires, or `deadline_ms` elapses.
    ///
    /// Returns `Ok(true)` for a change, `Ok(false)` for a timeout, and a typed
    /// [`ClipboardError::SignalConnectFailed`] if GLib refuses the signal.
    /// Registration is checked before the timeout is armed, so a refusal
    /// cannot leave a callback pointing at released wait state.
    ///
    /// # Why a signal and not a poll
    ///
    /// A page's copy travels WebProcess → UIProcess → `WPEClipboard`, so the
    /// write lands at an unknown time. Re-reading
    /// [`change_count`](Self::change_count) in a sleep loop would either sample
    /// too early or burn the whole budget. The property notification returns
    /// immediately on change and pays the deadline only when nothing does.
    pub fn wait_for_change(&self, deadline_ms: u32) -> Result<bool, ClipboardError> {
        // SAFETY: NULL context = default; rc=1.
        let main_loop = unsafe { wpe::g_main_loop_new(ptr::null_mut(), wpe::G_FALSE) };
        // INVARIANT: glib aborts on OOM rather than returning NULL.
        assert!(!main_loop.is_null(), "g_main_loop_new returned NULL");
        struct LoopGuard(*mut wpe::GMainLoop);
        impl Drop for LoopGuard {
            fn drop(&mut self) {
                // SAFETY: the loop; all users of it have already been retired.
                unsafe { wpe::g_main_loop_unref(self.0) };
            }
        }
        let _loop_guard = LoopGuard(main_loop);

        let mut backend = NativeChangeWait {
            clipboard: self.ptr,
            main_loop,
        };
        run_change_wait(
            &mut backend,
            deadline_ms,
            ChangeWait {
                main_loop,
                changed: false,
                deadline_fired: false,
                #[cfg(test)]
                drop_probe: None,
            },
        )
    }
}

/// Wrapper for [`wpe::g_free`] matching the `unsafe fn(*mut c_void)` signature
/// used by [`clipboard_bound::convert_native_text`].
///
/// # Safety
///
/// `ptr` must be NULL or a pointer allocated by glib (`g_malloc` / `g_strdup`).
unsafe fn native_free(ptr: *mut c_void) {
    unsafe { wpe::g_free(ptr) };
}

/// Convenience for a gate/diagnostic: on `display`, record the change count,
/// write `text`, record the new change count, and read the text back. Returns
/// `(before, after, readback)`.
pub fn clipboard_probe(
    display: &HeadlessDisplay,
    text: &str,
) -> Result<(i64, i64, Option<String>), ClipboardError> {
    let clip = Clipboard::for_display(display)?;
    let before = clip.change_count();
    clip.set_text(text)?;
    let after = clip.change_count();
    let readback = clip.read_text()?;
    Ok((before, after, readback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Clone, Copy)]
    enum Outcome {
        Refused,
        Changed,
        TimedOut,
    }

    struct FakeBackend {
        outcome: Outcome,
        events: Vec<&'static str>,
        disconnects: usize,
        source_removals: usize,
    }

    impl FakeBackend {
        fn new(outcome: Outcome) -> Self {
            Self {
                outcome,
                events: Vec::new(),
                disconnects: 0,
                source_removals: 0,
            }
        }
    }

    impl ChangeWaitBackend for FakeBackend {
        fn connect(&mut self, _state: *mut ChangeWait) -> u64 {
            self.events.push("connect");
            match self.outcome {
                Outcome::Refused => 0,
                Outcome::Changed | Outcome::TimedOut => 41,
            }
        }

        fn arm_timeout(&mut self, _deadline_ms: u32, _state: *mut ChangeWait) -> u32 {
            self.events.push("arm-timeout");
            73
        }

        fn run(&mut self, state: *mut ChangeWait) {
            self.events.push("run");
            // SAFETY: `run_change_wait` owns this state for the whole call.
            let state = unsafe { &mut *state };
            match self.outcome {
                Outcome::Refused => unreachable!("refusal must not run"),
                Outcome::Changed => state.changed = true,
                Outcome::TimedOut => {
                    if mark_change_deadline(state) == wpe::G_FALSE {
                        self.source_removals += 1;
                    }
                }
            }
        }

        fn disconnect(&mut self, handler: u64) {
            assert_eq!(handler, 41);
            self.events.push("disconnect");
            self.disconnects += 1;
        }

        fn remove_timeout(&mut self, source: u32) {
            assert_eq!(source, 73);
            self.events.push("remove-timeout");
            self.source_removals += 1;
        }
    }

    fn state(drop_probe: Rc<Cell<usize>>) -> ChangeWait {
        ChangeWait {
            main_loop: ptr::null_mut(),
            changed: false,
            deadline_fired: false,
            drop_probe: Some(drop_probe),
        }
    }

    #[test]
    fn clipboard_change_wait_signal_refusal_is_typed_and_arms_no_timeout() {
        let drops = Rc::new(Cell::new(0));
        let mut backend = FakeBackend::new(Outcome::Refused);

        let result = run_change_wait(&mut backend, 10, state(Rc::clone(&drops)));

        assert_eq!(
            result,
            Err(ClipboardError::SignalConnectFailed {
                context: CHANGE_SIGNAL,
            })
        );
        assert_eq!(backend.events, ["connect"]);
        assert_eq!(backend.disconnects, 0, "zero is not a live handler");
        assert_eq!(backend.source_removals, 0, "no timeout was armed");
        assert_eq!(drops.get(), 1, "callback state must be dropped once");
    }

    #[test]
    fn clipboard_change_wait_success_disconnects_and_removes_once() {
        let drops = Rc::new(Cell::new(0));
        let mut backend = FakeBackend::new(Outcome::Changed);

        let result = run_change_wait(&mut backend, 10, state(Rc::clone(&drops)));

        assert_eq!(result, Ok(true));
        assert_eq!(
            backend.events,
            [
                "connect",
                "arm-timeout",
                "run",
                "disconnect",
                "remove-timeout"
            ]
        );
        assert_eq!(backend.disconnects, 1);
        assert_eq!(backend.source_removals, 1);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn clipboard_change_wait_timeout_disconnects_and_self_removes_once() {
        let drops = Rc::new(Cell::new(0));
        let mut backend = FakeBackend::new(Outcome::TimedOut);

        let result = run_change_wait(&mut backend, 10, state(Rc::clone(&drops)));

        assert_eq!(result, Ok(false));
        assert_eq!(
            backend.events,
            ["connect", "arm-timeout", "run", "disconnect"]
        );
        assert_eq!(backend.disconnects, 1);
        assert_eq!(backend.source_removals, 1);
        assert_eq!(drops.get(), 1);
    }
}
