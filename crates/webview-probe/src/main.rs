//! `webview-probe`: one window that drives `enzui-webkit` through
//! `enzui-webview`, so every protocol hop - policy, focus handoff, frame
//! delivery, page accessibility, IME, cursor, clipboard and the real WPE page -
//! can be clicked, screenshotted and tested through `App::update`.
//!
//! Feature-off it is deterministic: the native backend resolves to a typed
//! `NativeUnavailable`, which the status line shows rather than substituting a
//! mock. Build with `--features wpe` to open a real page.
//!
//! `ENZUI_PROBE_LIGHT=1` selects the light theme; dark is the default.

mod diagnostic_log;
mod message;
mod native_interest;
mod routes;
mod update;
mod webview;
mod webview_native;
mod webview_scratch;

#[cfg(test)]
mod tests;

mod app;
pub(crate) use app::App;

pub(crate) use message::{Message, drain_a11y_actions, drain_a11y_wake};

pub fn main() -> iced::Result {
    #[cfg(feature = "diagnostics")]
    if std::env::args().any(|arg| arg == "--clipboard-check") {
        let scratch = webview_scratch::SecureScratch::open_for_native_webview()
            .expect("private clipboard scratch");
        webview_native::run_clipboard_gate(scratch.path().to_path_buf()).expect("clipboard gate");
        return Ok(());
    }

    #[cfg(feature = "diagnostics")]
    if std::env::args().any(|arg| arg == "--metadata-check") {
        let scratch = webview_scratch::SecureScratch::open_for_native_webview()
            .expect("private metadata scratch");
        webview_native::run_metadata_gate(scratch.path().to_path_buf()).expect("metadata gate");
        return Ok(());
    }

    // The accessibility bridge is seated before the first window and owned for
    // the whole loop.
    enzui_core::app_runtime::run(|| {
        iced::application(App::boot, App::update, App::view)
            .title(App::title)
            .window_size((1280.0, 800.0))
            .theme(App::theme)
            .subscription(App::subscription)
            .run()
    })
}
