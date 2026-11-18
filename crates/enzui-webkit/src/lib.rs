//! Typed WebView engine and protocol layer over WPE WebKit, with no UI toolkit.
//!
//! Toolkit adapters such as `enzui-webview` present a page. This crate owns the
//! native session, policy, input and frame protocol; native code requires the
//! `wpe` feature.
//!

// `deny(unsafe_code)` is the crate default. Narrow module allowances mark the
// native FFI boundary, native clipboard allocation conversion, the raw-pointer
// abandoned-operation state transition, and GLib deadline-source removal.
#![deny(unsafe_code)]

#[cfg(any(feature = "wpe", test))]
#[allow(unsafe_code)]
mod abandoned_operation;
#[allow(unsafe_code)]
pub(crate) mod clipboard_bound;
pub mod clipboard_route;
// The shared bounded reader for NUL-terminated native diagnostics (GLib
// `GError` messages). Pure and always compiled so its bounding is testable
// feature-off; the feature-on FFI readers call it under their pointer
// contracts.
pub mod destination_guard;
// The per-family `getaddrinfo` binding behind the guard's system resolver.
#[allow(unsafe_code)]
pub(crate) mod name_lookup;
#[allow(unsafe_code)]
pub(crate) mod native_diagnostic;
// Native deadline retirement and its tests use the feature-on FFI boundary.
#[cfg(feature = "wpe")]
#[allow(unsafe_code)]
mod deadline_source;
// Only compiled feature-on; feature-off preserves the "no WPE dependency"
// requirement by emitting no `extern "C"` declarations at all.
#[cfg(feature = "wpe")]
pub mod ffi;
pub mod frame;
pub mod frame_damage;
pub mod frame_plan;
pub mod ime_bridge;
pub mod input;
pub mod mode;
// The observable consequence of destroying a page. Always compiled so a
// feature-off build can prove the ledger cannot advance without WPE; only the
// real owners' `Drop` (feature-on) ever records.
pub mod native_release;
pub mod page;
pub mod page_a11y;
pub mod page_action;
pub mod page_delivery;
mod panic_boundary;
// Pure media-permission classification. Always compiled and free of `unsafe`:
// the WPE callback reads the native device flags and delegates the decision
// here, so the mapping is testable with no WebKit, display or capture device.
pub mod permission_map;
pub mod profile_fs;
pub mod protocol;
pub mod sandbox;
pub mod session;
pub mod tab_focus;
pub mod tab_memory;
pub mod viewport;
pub mod visibility;
pub mod web;
// Bounded, crowd-out-proof teardown for a thread-affine page worker.
// Always compiled: the teardown protocol is pure Rust and is therefore testable
// on a feature-off build, where no WPE runtime exists.
pub mod worker;

pub use clipboard_route::{
    ClipboardDirection, ClipboardOutcome, ClipboardRouteError, HostGesture, HostPaste, PageCopy,
};
pub use destination_guard::{DestinationGuard, GuardEvent};
pub use ime_bridge::{ImeEffect, ImeTransition, NativeImeReport, WebViewIme};
pub use input::{
    InputEvent, KeyCode, NamedKey, PointerButton, ViewPoint, ViewportMapping, pointer_moved,
    pointer_pressed, pointer_released, wheel_scrolled,
};
pub use mode::{BackendMode, ModeError, ResolvedBackend};
pub use page_a11y::{
    AccessibleSource, PageA11y, PageAction, PageActionTarget, PageLimits, PageNode,
    PageNodeAddress, PageNodeKey,
};
pub use page_delivery::{PageA11yDelivery, PageActionRoute, PageDelivery};
pub use protocol::{EngineCommand, EngineEvent};
pub use sandbox::{OuterSandbox, SandboxAttestation, SandboxRefusal, UnattestedReason};
pub use session::{PolicySession, SessionResolve, ViewRequestId};
pub use tab_focus::{
    NativeFocusToken, NativeTabSignal, observe_native_tab, parse_native_focus_token,
};
pub use viewport::{ViewportSize, ViewportSizeError};
pub use visibility::{FrameRequest, ViewLifecycle, ViewVisibility};

#[cfg(feature = "wpe")]
mod page_event_queue;

pub mod local_origins;

pub mod content_filter;
pub mod printing;
pub mod site_data;
pub mod site_permissions;

pub mod page_export;
pub mod resource;

pub mod favicon;
