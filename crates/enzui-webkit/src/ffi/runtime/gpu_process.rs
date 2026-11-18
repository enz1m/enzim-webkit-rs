//! WebKit's GPU process: one sandboxed process that does GPU work for every
//! view of the runtime instead of each web process doing its own.
//!
//! On request it runs WebGL, and paints tiles and composites layers for every
//! page. A web process decides when it creates its first page, so a request
//! applies to views created after it.
use super::*;

thread_local! {
    static WEBGL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static COMPOSITING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run the WebGL of views created from now on in the GPU process.
///
/// Call on the native owner thread before creating the sessions it should
/// apply to; a web process that already shows a page keeps rendering WebGL
/// itself. The default is off.
pub fn set_gpu_process_for_webgl(enabled: bool) {
    WEBGL.with(|webgl| webgl.set(enabled));
}

/// Paint and composite the pages of views created from now on in the GPU
/// process.
///
/// Web processes then hold no GL context and no tile textures: one process
/// keeps the GPU memory of every page, and hardware-decoded video reaches it
/// without a copy. Call on the native owner thread before creating the
/// sessions it should apply to; a web process that already shows a page
/// keeps compositing itself. The default is off.
pub fn set_gpu_process_for_compositing(enabled: bool) {
    COMPOSITING.with(|compositing| compositing.set(enabled));
}

/// Apply the requests to a view before it loads anything; whether they hold.
pub(super) fn apply(web_view: *mut ffi::WebKitWebView) -> bool {
    let features = [
        (WEBGL.with(std::cell::Cell::get), "UseGPUProcessForWebGL"),
        (
            COMPOSITING.with(std::cell::Cell::get),
            "UseGPUProcessForCompositing",
        ),
    ];
    features
        .into_iter()
        .filter(|(requested, _)| *requested)
        .all(|(_, feature)| {
            // SAFETY: the view was just constructed on this thread.
            unsafe { crate::ffi::page::enable_feature(web_view, feature) }
        })
}
