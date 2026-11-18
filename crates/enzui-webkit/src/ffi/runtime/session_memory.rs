//! Releasing a background page's web process memory on the host's request.
//!
//! WebKit on Linux trims a web process by itself only under system memory
//! pressure or once the process passes about a gigabyte. A host that knows a
//! page is in the background, as a browser knows of an inactive tab, asks for
//! the release that WebKit performs for a process about to be suspended.
use super::*;
use std::sync::OnceLock;

type Release = unsafe extern "C" fn(*mut ffi::WebKitWebView);
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
fn release_api() -> Option<Release> {
    static API: OnceLock<Option<Release>> = OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: a fixed fork symbol is resolved from already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                ptr::null_mut(),
                c"webkit_web_view_enzui_release_memory_v1".as_ptr(),
            )
        };
        // SAFETY: the function uses the reviewed fork's exact C ABI.
        (!symbol.is_null()).then(|| unsafe { std::mem::transmute::<*mut c_void, Release>(symbol) })
    })
}

fn idle_release_api() -> Option<Release> {
    static API: OnceLock<Option<Release>> = OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: a fixed fork symbol is resolved from already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                ptr::null_mut(),
                c"webkit_web_view_enzui_release_idle_memory_v1".as_ptr(),
            )
        };
        // SAFETY: the function uses the reviewed fork's exact C ABI.
        (!symbol.is_null()).then(|| unsafe { std::mem::transmute::<*mut c_void, Release>(symbol) })
    })
}

/// The runtime predates memory release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryReleaseUnsupported;

impl std::fmt::Display for MemoryReleaseUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the runtime cannot release a page's memory")
    }
}

impl std::error::Error for MemoryReleaseUnsupported {}

impl WebSession {
    /// Ask the web processes showing this page to release memory now.
    ///
    /// They drop compiled JavaScript, decoded images and other resources,
    /// style and font caches, then collect garbage and return freed heap to
    /// the system. A hidden page also drops its tiles, a frame the host has
    /// not taken, and every compositor buffer but the one holding a frame the
    /// host keeps; showing it repaints the visible part. The page stays loaded
    /// and keeps its state; it rebuilds what it needs when used again, so the
    /// next interaction can be slower. Suits a page the user is not looking
    /// at, such as a tab that has been in the background for a while, after
    /// [`Self::set_view_visibility`] hid it.
    /// The release is asynchronous; other pages sharing a process are released
    /// with it.
    ///
    /// # Errors
    /// [`MemoryReleaseUnsupported`] on a runtime without the request.
    pub fn release_memory(&self) -> Result<(), MemoryReleaseUnsupported> {
        let release = release_api().ok_or(MemoryReleaseUnsupported)?;
        self.discard_hidden_gpu_frame();
        // SAFETY: the session's view is live on its owning thread.
        unsafe { release(self.web_view) };
        Ok(())
    }

    /// Ask the web processes showing this page to drop what is free to drop.
    ///
    /// They collect garbage and return unused heap to the system, and clear
    /// caches that rebuild on demand. Compiled JavaScript, decoded images of
    /// live resources, the memory cache and the back/forward cache stay, so a
    /// page that is shown again behaves as if nothing happened. Meant for a
    /// page shortly after it is hidden, ahead of [`WebSession::release_memory`].
    ///
    /// # Errors
    /// [`MemoryReleaseUnsupported`] on a runtime without the request.
    pub fn release_idle_memory(&self) -> Result<(), MemoryReleaseUnsupported> {
        let release = idle_release_api().ok_or(MemoryReleaseUnsupported)?;
        // SAFETY: the session's view is live on its owning thread.
        unsafe { release(self.web_view) };
        Ok(())
    }
}
