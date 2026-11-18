//! FFI bindings to the WPE WebKit 2.0 C API, compiled only with the `wpe`
//! feature.
//!

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod wpe;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod runtime;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod deployment;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod clipboard;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod cursor;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod page;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod ime;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod a11y;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod profile;

#[cfg(feature = "wpe")]
#[allow(
    unsafe_code,
    reason = "GLib task cancellation and native callback ownership."
)]
pub mod native_task;

#[cfg(feature = "wpe")]
#[allow(
    unsafe_code,
    reason = "Native cookie and website-data callbacks and owned metadata extraction."
)]
pub mod site_data;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod policy;

#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
pub mod signal;

#[cfg(feature = "wpe")]
pub use clipboard::{Clipboard, ClipboardError, MAX_CLIPBOARD_TEXT_BYTES, clipboard_probe};

#[cfg(feature = "wpe")]
pub use ime::{ImeContext, ImeInstallError, PageImeReport};

#[cfg(feature = "wpe")]
#[allow(
    unsafe_code,
    reason = "native version and calling-thread predicates do not initialize WPE"
)]
mod threading;

#[cfg(feature = "wpe")]
pub use threading::{
    NativeInterest, NativeInterestError, NativeThreadError, dispatch_pending_native_events,
    native_event_interest, native_requires_process_main_thread, wake_native_event_loop,
};

#[cfg(feature = "wpe")]
#[allow(
    unsafe_code,
    reason = "WPEPlatform buffer ownership and native presentation callbacks"
)]
pub mod presentation;

#[cfg(feature = "wpe")]
#[allow(
    unsafe_code,
    reason = "native version accessors return immutable library metadata"
)]
mod versions;

#[cfg(feature = "wpe")]
pub use versions::{NativeRuntimeVersions, native_runtime_versions};

#[cfg(feature = "wpe")]
pub use runtime::content_filters;

#[cfg(feature = "wpe")]
pub use runtime::resource_log;
