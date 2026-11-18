//! The colour chooser request. WPE WebKit has it from 2.56; a build linked
//! against an older library still runs with the newer runtime, so the calls
//! are resolved from what is loaded, and absent together where it has none.
use super::*;

/// `WebKitColor` (WebKitColor.h): four `gdouble`s between 0 and 1.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct WebKitColor {
    pub(super) red: f64,
    pub(super) green: f64,
    pub(super) blue: f64,
    pub(super) alpha: f64,
}

#[repr(C)]
pub(super) struct WebKitColorChooserRequest {
    _priv: [u8; 0],
}

type Request = *mut WebKitColorChooserRequest;
type GetColor = unsafe extern "C" fn(Request, *mut WebKitColor);
type SetColor = unsafe extern "C" fn(Request, *const WebKitColor);
type GetRectangle = unsafe extern "C" fn(Request, *mut WebKitRectangle);
type GetFlag = unsafe extern "C" fn(Request) -> ffi::GBoolean;
type End = unsafe extern "C" fn(Request);

/// The request's functions, each with the signature of
/// `WebKitColorChooserRequest.h`.
#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) get_color: GetColor,
    pub(super) set_color: SetColor,
    pub(super) get_element_rectangle: GetRectangle,
    pub(super) get_supports_alpha: GetFlag,
    pub(super) finish: End,
    pub(super) cancel: End,
}

/// The loaded runtime's colour chooser, if it has one.
pub(super) fn api() -> Option<Api> {
    static API: std::sync::OnceLock<Option<Api>> = std::sync::OnceLock::new();
    *API.get_or_init(|| {
        let find = frame_secrets::symbol;
        let symbols = [
            find(c"webkit_color_chooser_request_get_color"),
            find(c"webkit_color_chooser_request_set_color"),
            find(c"webkit_color_chooser_request_get_element_rectangle"),
            find(c"webkit_color_chooser_request_get_supports_alpha"),
            find(c"webkit_color_chooser_request_finish"),
            find(c"webkit_color_chooser_request_cancel"),
        ];
        if symbols.iter().any(|symbol| symbol.is_null()) {
            return None;
        }
        // SAFETY: each non-null symbol is the function of that name in the
        // loaded WPE WebKit, whose C signature the field's type restates.
        Some(unsafe {
            Api {
                get_color: std::mem::transmute::<*mut c_void, GetColor>(symbols[0]),
                set_color: std::mem::transmute::<*mut c_void, SetColor>(symbols[1]),
                get_element_rectangle: std::mem::transmute::<*mut c_void, GetRectangle>(symbols[2]),
                get_supports_alpha: std::mem::transmute::<*mut c_void, GetFlag>(symbols[3]),
                finish: std::mem::transmute::<*mut c_void, End>(symbols[4]),
                cancel: std::mem::transmute::<*mut c_void, End>(symbols[5]),
            }
        })
    })
}
