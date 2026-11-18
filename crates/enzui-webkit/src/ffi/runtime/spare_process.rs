//! A spare web process kept ready for the next page.
//!
//! A navigation that leaves its process (to another site, or to a response
//! with `Cross-Origin-Opener-Policy`) and a new view each need a web process.
//! With a spare one ready the page does not wait for a launch, about 60 ms;
//! the price is one idle process, which memory pressure ends.
use super::*;
use std::sync::OnceLock;

type SetSpare = unsafe extern "C" fn(*mut c_void, c_int);

#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

fn api() -> Option<SetSpare> {
    static API: OnceLock<Option<SetSpare>> = OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: a fixed fork symbol is resolved from already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                ptr::null_mut(),
                c"webkit_web_context_enzui_set_spare_web_process_v1".as_ptr(),
            )
        };
        // SAFETY: the symbol, when present, has the reviewed fork's exact C ABI.
        (!symbol.is_null()).then(|| unsafe { std::mem::transmute::<*mut c_void, SetSpare>(symbol) })
    })
}

/// The runtime cannot keep a spare web process for the profile in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpareProcessUnsupported;

impl std::fmt::Display for SpareProcessUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the runtime cannot keep a spare web process")
    }
}

impl std::error::Error for SpareProcessUnsupported {}

/// Keep a spare web process for the profile of the newest page, or none.
///
/// Call on the native owner thread. Without a call WebKit decides itself and
/// starts keeping one after its first navigation to another process.
///
/// # Errors
/// [`SpareProcessUnsupported`] on a runtime without the choice; it may keep
/// spare processes it never uses.
pub fn set_spare_web_process(enabled: bool) -> Result<(), SpareProcessUnsupported> {
    let set = api().ok_or(SpareProcessUnsupported)?;
    // SAFETY: the default context is a live process-global object on the
    // native owner thread.
    unsafe {
        set(
            ffi::webkit_web_context_get_default().cast(),
            c_int::from(enabled),
        )
    };
    Ok(())
}
