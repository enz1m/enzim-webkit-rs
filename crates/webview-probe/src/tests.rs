//! Source-adjacent tests: `cfg(test)`-only, with `App`/`Message` access and no
//! widened production visibility.

/// `WebViewClose` revokes authorities, joins natives, frees buffers; reopen mints later ids.
mod webview_close_teardown;
/// Engine route: late policy replies to gone views resolve `ViewGone`, never decide.
/// Bounded native queue: typed refusals survive ordinary traffic pressure.
mod webview_native_queue;
/// Terminal fallback preserves admission order: no stuck-grabbed pages after saturation.
mod webview_native_terminal_fallback_order;
/// The `webview` route wire test proves the probe route reaches
/// `enzui_webkit::web` (policy, focus, frame, profile, view_id).
mod webview_route_wire;
