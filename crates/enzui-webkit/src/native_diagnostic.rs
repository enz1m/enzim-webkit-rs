//! Bounded reading of NUL-terminated native diagnostic strings.
//!
//! GLib `GError` messages are library/page diagnostics of unbounded native
//! length. Every other native-string reader in this crate caps its read; this
//! is the shared reader those `GError` message paths converge on so a
//! pathological message cannot force an unbounded allocation. The logic is
//! pure Rust with no WPE dependency, so its tests run without `--features wpe`;
//! the WPE-gated `ffi::a11y` and `ffi::profile` readers call it from an
//! `unsafe` block where the raw-pointer invariants are established by the C API
//! contract.

// `unsafe_code` is allowed for this module by the `#[allow(unsafe_code)]` on its
// `mod native_diagnostic;` declaration in `lib.rs`.
// The items here are consumed only by feature-gated FFI readers; suppress
// dead-code warnings in feature-off builds while keeping them available for the
// always-compiled tests.
#![cfg_attr(not(feature = "wpe"), allow(dead_code))]

use std::ffi::c_char;

/// Byte ceiling for a single native diagnostic string.
///
/// A `GError` message is display text, not a routing identity; 16 KiB is far
/// above any legitimate diagnostic while preventing a hostile page or library
/// from turning one message into an arbitrary allocation.
pub const MAX_NATIVE_DIAGNOSTIC_BYTES: usize = 16 * 1024;

/// Read a NUL-terminated native diagnostic into a bounded, lossy `String`.
///
/// Scans at most `max_bytes + 1` bytes for the terminator. A message whose
/// content is at most `max_bytes` bytes is returned with invalid UTF-8 replaced
/// (diagnostics are display text, so a lossy read is preferred to a refusal). A
/// message with no terminator within the ceiling yields a placeholder naming
/// the limit rather than a truncated, attacker-controlled prefix.
///
/// # Safety
///
/// `ptr` must be non-null and point to a NUL-terminated C string readable
/// through its terminator or through `max_bytes + 1` bytes, whichever comes
/// first.
pub(crate) unsafe fn read_bounded_diagnostic(ptr: *const c_char, max_bytes: usize) -> String {
    for len in 0..=max_bytes {
        // SAFETY: the caller guarantees a NUL-terminated string, so every byte
        // through the first NUL is readable; the scan stops at the ceiling, so
        // it never reads past `max_bytes + 1` bytes.
        if unsafe { *ptr.add(len) } == 0 {
            // SAFETY: the scan just established `len` readable bytes before the
            // NUL.
            let raw = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
            return String::from_utf8_lossy(raw).into_owned();
        }
    }
    format!("(diagnostic message exceeds {max_bytes} bytes)")
}
