//! The name the desktop knows the host by.
//!
//! WebKit's sandbox presents web processes to the desktop portals as an
//! application: the screen-sharing picker names it, and the portals keep their
//! permissions for it. WebKit takes the id from the default `GApplication`, or
//! from the program name when that is a valid application id, and otherwise
//! makes one up from a hash of the executable path.
use super::*;

unsafe extern "C" {
    fn g_set_prgname(name: *const c_char);
    fn g_application_id_is_valid(id: *const c_char) -> ffi::GBoolean;
}

/// Name the host to the desktop by `id`, its application id (the name of its
/// `.desktop` file without the suffix), as GLib's program name.
///
/// Call it before the first view: WebKit reads the id once. Returns whether
/// `id` is a valid application id and was set.
pub fn set_application_id(id: &str) -> bool {
    let Ok(id) = std::ffi::CString::new(id) else {
        return false;
    };
    // SAFETY: a NUL-terminated string; GLib copies the program name.
    unsafe {
        if g_application_id_is_valid(id.as_ptr()) == 0 {
            return false;
        }
        g_set_prgname(id.as_ptr());
    }
    true
}
