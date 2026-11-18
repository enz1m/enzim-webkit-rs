//! Confirmed geolocation revocation through the reviewed native runtime.
use super::*;
use crate::page::{PageEvent, PageRequestId};
use std::sync::OnceLock;

type Revoke = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    *mut c_void,
    extern "C" fn(*mut c_void, *mut ffi::GAsyncResult, *mut c_void),
    *mut c_void,
);
type Finish = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    *mut ffi::GAsyncResult,
    *mut *mut ffi::GError,
) -> ffi::GBoolean;
struct Api {
    revoke: Revoke,
    finish: Finish,
    reset: Revoke,
    reset_finish: Finish,
}
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: fixed fork symbols are resolved from already loaded native libraries.
        let (revoke, finish) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_revoke_geolocation".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_revoke_geolocation_finish".as_ptr(),
                ),
            )
        };
        // SAFETY: the reset pair uses the same reviewed asynchronous ABI.
        let (reset, reset_finish) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_reset_geolocation_permission".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_reset_geolocation_permission_finish".as_ptr(),
                ),
            )
        };
        if revoke.is_null() || finish.is_null() || reset.is_null() || reset_finish.is_null() {
            return None;
        }
        // SAFETY: these functions use the reviewed fork's exact asynchronous C ABI.
        Some(unsafe {
            Api {
                revoke: std::mem::transmute::<*mut c_void, Revoke>(revoke),
                finish: std::mem::transmute::<*mut c_void, Finish>(finish),
                reset: std::mem::transmute::<*mut c_void, Revoke>(reset),
                reset_finish: std::mem::transmute::<*mut c_void, Finish>(reset_finish),
            }
        })
    })
    .as_ref()
}
struct Completion {
    hub: std::rc::Weak<crate::ffi::page::PageHub>,
    id: PageRequestId,
    revoked: bool,
    finish: Finish,
}
extern "C" fn finished(view: *mut c_void, result: *mut ffi::GAsyncResult, data: *mut c_void) {
    // SAFETY: the native async completion consumes the one boxed callback allocation.
    let completion = unsafe { Box::from_raw(data.cast::<Completion>()) };
    let mut error = ptr::null_mut();
    // SAFETY: native code supplies the matching view and result for this operation.
    let success = unsafe { (completion.finish)(view.cast(), result, &mut error) };
    let result = if success != 0 && error.is_null() {
        Ok(())
    } else {
        let message = if error.is_null() {
            "native geolocation revocation failed".to_owned()
        } else {
            // SAFETY: finish returned an owned error whose message is valid through free.
            let message = unsafe {
                crate::native_diagnostic::read_bounded_diagnostic((*error).message, 2048)
            };
            // SAFETY: the finish call transferred this error reference.
            unsafe { ffi::g_error_free(error) };
            message
        };
        Err(message)
    };
    if let Some(hub) = completion.hub.upgrade() {
        hub.push(PageEvent::GeolocationPermissionChanged {
            id: completion.id,
            revoked: completion.revoked,
            result,
        });
    }
}
impl WebSession {
    /// Whether native origin metadata and permission-history/revocation support are available.
    /// Older runtimes must retain the legacy permission policy instead of promising per-site grants.
    pub fn supports_origin_permissions(&self) -> bool {
        api().is_some() && crate::ffi::page::permissions::has_media_history_api()
    }

    /// Stop existing geolocation watches throughout this view, independently of navigation policy.
    ///
    /// Completion arrives as [`PageEvent::GeolocationPermissionChanged`] after native acknowledgement.
    /// Native failure or an acknowledgement timeout terminates the involved renderers.
    /// This clears current watches, not stored host choices. Drive native dispatch
    /// until completion before reporting revocation as finished.
    ///
    /// # Errors
    /// Returns [`SessionError::OriginPermissionsUnsupported`] without native support.
    pub fn revoke_geolocation(&self) -> Result<PageRequestId, SessionError> {
        self.change_geolocation_permission(true)
    }

    /// Clear cached geolocation denials without granting permission or stopping allowed watches.
    ///
    /// Completion arrives as [`PageEvent::GeolocationPermissionChanged`] with this
    /// operation ID and `revoked: false` after native acknowledgement.
    ///
    /// # Errors
    /// Returns [`SessionError::OriginPermissionsUnsupported`] without native support.
    pub fn reset_geolocation_permission(&self) -> Result<PageRequestId, SessionError> {
        self.change_geolocation_permission(false)
    }

    pub(super) fn change_geolocation_permission(
        &self,
        revoked: bool,
    ) -> Result<PageRequestId, SessionError> {
        let api = api().ok_or(SessionError::OriginPermissionsUnsupported)?;
        let id = self.page_hub.new_operation_id();
        let completion = Box::new(Completion {
            hub: Rc::downgrade(&self.page_hub),
            id,
            revoked,
            finish: if revoked {
                api.finish
            } else {
                api.reset_finish
            },
        });
        // SAFETY: this owner retains the view; the native task consumes its callback allocation exactly once.
        unsafe {
            (if revoked { api.revoke } else { api.reset })(
                self.web_view,
                ptr::null_mut(),
                finished,
                Box::into_raw(completion).cast(),
            )
        };
        Ok(id)
    }
}
