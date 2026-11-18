//! Clipboard text read bounding - not feature-gated.
//!
//! The bounded-read logic and its ceiling are pure Rust with no WPE dependency,
//! so tests run without `--features wpe`. The WPE-gated [`crate::ffi::clipboard`]
//! module calls [`convert_native_text`] from an `unsafe` block in the FFI
//! wrapper where the raw-pointer invariants are established by the C API
//! contract.

// `unsafe_code` is already allowed for this module by the `#[allow(unsafe_code)]`
// on its `mod clipboard_bound;` declaration in `lib.rs`; a second inner allow
// here would be a duplicated attribute.
// The items here are consumed by `ffi::clipboard` which is behind
// `#[cfg(feature = "wpe")]`; suppress dead-code warnings in feature-off
// builds while keeping them available for the always-compiled tests.
#![cfg_attr(not(feature = "wpe"), allow(dead_code))]

use core::ffi::c_void;
use std::ffi::c_char;

/// Maximum clipboard text bytes accepted from the native layer.
///
/// Any native read reporting a size above this ceiling is refused with
/// `ClipboardReadError::TextTooLarge` rather than allocated. 4 MiB covers
/// any legitimate paste while preventing an arbitrary allocation forced by a
/// malicious clipboard owner or page.
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// A bounded clipboard read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardReadError {
    /// The native clipboard returned text exceeding
    /// [`MAX_CLIPBOARD_TEXT_BYTES`].
    TextTooLarge {
        /// Reported native size in bytes.
        size: usize,
    },
}

impl std::fmt::Display for ClipboardReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClipboardReadError::TextTooLarge { size } => write!(
                f,
                "clipboard text too large ({size} bytes, limit {MAX_CLIPBOARD_TEXT_BYTES})",
            ),
        }
    }
}

impl std::error::Error for ClipboardReadError {}

/// Convert a native clipboard read result to a bounded [`String`].
///
/// # Safety
///
/// The caller must guarantee all of the following:
///
/// * If `raw` is non-null it must point to a single allocation of at least
///   `native_size` readable bytes. WPE reports the exact `GBytes` payload
///   length, excluding any terminator; this function reads exactly that span.
/// * `free_fn` must be the deallocator that matches the allocator that
///   produced `raw` (e.g. `g_free` for a `g_malloc`'d pointer, or
///   `libc::free` for a `libc::malloc`'d pointer in tests).
/// * `raw` must not be used after this call returns - ownership is
///   transferred; the pointer is freed exactly once on every non-null path.
pub(crate) unsafe fn convert_native_text(
    raw: *mut c_char,
    native_size: usize,
    free_fn: unsafe fn(*mut c_void),
) -> Result<Option<String>, ClipboardReadError> {
    if raw.is_null() {
        return Ok(None);
    }
    if native_size > MAX_CLIPBOARD_TEXT_BYTES {
        // SAFETY: caller guaranteed `raw` is a live allocation and
        // `free_fn` is its paired deallocator.
        unsafe { free_fn(raw.cast::<c_void>()) };
        return Err(ClipboardReadError::TextTooLarge { size: native_size });
    }
    // SAFETY: caller guaranteed `raw` points to at least `native_size`
    // readable bytes in a single allocation.
    let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), native_size) };
    let owned = String::from_utf8_lossy(bytes).into_owned();
    // SAFETY: free the native-allocated string; caller guaranteed pairing.
    unsafe { free_fn(raw.cast::<c_void>()) };
    Ok(Some(owned))
}

// ---------------------------------------------------------------------------
// Unit tests - mock allocator seam, no WPE needed.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Per-thread counter for `mock_free` calls, isolated across parallel
    // tests (each test runs on its own thread).
    thread_local! {
        static FREE_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    fn reset_free_count() {
        FREE_COUNT.with(|c| c.set(0));
    }

    fn get_free_count() -> usize {
        FREE_COUNT.with(|c| c.get())
    }

    /// Mock free that increments the thread-local [`FREE_COUNT`] and delegates
    /// to `libc::free`.
    ///
    /// # Safety
    ///
    /// `ptr` must be NULL or allocated by `libc::malloc`.
    unsafe fn mock_free(ptr: *mut c_void) {
        FREE_COUNT.with(|c| c.set(c.get() + 1));
        unsafe { libc::free(ptr) };
    }

    /// Allocate `n` bytes with `libc::malloc`, fill with `fill`, return the
    /// pointer. Panics on allocation failure.
    fn mock_alloc(n: usize, fill: u8) -> *mut c_char {
        assert!(n > 0);
        let ptr = unsafe { libc::malloc(n) };
        assert!(!ptr.is_null(), "mock_alloc: malloc returned NULL");
        unsafe { std::ptr::write_bytes(ptr, fill, n) };
        ptr.cast()
    }

    #[test]
    fn oversized_native_text_refused_and_freed_once() {
        reset_free_count();
        // Allocate a tiny buffer but claim a size above the ceiling.
        // The oversized path frees without reading, so 4 bytes suffices.
        let ptr = mock_alloc(4, b'X');
        let oversized = MAX_CLIPBOARD_TEXT_BYTES + 1;
        // SAFETY: `ptr` is a live `libc::malloc` allocation of 4 bytes.
        // This code passes `oversized` as the *reported* native size to trigger the
        // refusal path, which frees without reading - so the allocation
        // validity for `oversized` bytes is never exercised (the bound
        // check fires first). `mock_free` matches `libc::malloc`.
        let result = unsafe { convert_native_text(ptr, oversized, mock_free) };
        match result {
            Err(ClipboardReadError::TextTooLarge { size }) => {
                assert_eq!(size, oversized, "reported size must match");
            }
            other => panic!("expected TextTooLarge, got {other:?}"),
        }
        assert_eq!(
            get_free_count(),
            1,
            "exactly-once cleanup on oversized refusal",
        );
    }
}
