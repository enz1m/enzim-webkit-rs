//! Certificate exceptions recorded on the network session that holds them.
//!
//! `webkit_network_session_allow_tls_certificate_for_host` applies to every
//! view sharing that session for the session's lifetime, so the record lives
//! on the session object and is freed with it.

use super::ffi;
use core::ffi::c_void;
use std::cell::RefCell;
use std::collections::BTreeSet;

const KEY: &std::ffi::CStr = c"enzui-certificate-exception-hosts-v1";

type Hosts = RefCell<BTreeSet<String>>;

extern "C" fn free_hosts(data: *mut c_void) {
    // SAFETY: GLib calls this once for the box installed by `record`.
    drop(unsafe { Box::from_raw(data.cast::<Hosts>()) });
}

/// Records that `session` continues past a failed certificate for `host`.
///
/// # Safety
/// `session` is null or a live `WebKitNetworkSession` used on its owning thread.
pub(crate) unsafe fn record(session: *mut ffi::WebKitNetworkSession, host: &str) {
    if session.is_null() {
        return;
    }
    let Ok((_, key)) = super::certificate_authorization_identity(host) else {
        return;
    };
    // SAFETY: the caller supplies a live session; the data under KEY is only
    // ever a `Hosts` box installed below.
    unsafe {
        let hosts = ffi::g_object_get_data(session.cast(), KEY.as_ptr()).cast::<Hosts>();
        if let Some(hosts) = hosts.as_ref() {
            hosts.borrow_mut().insert(key);
            return;
        }
        let hosts: Box<Hosts> = Box::new(RefCell::new(BTreeSet::from([key])));
        ffi::g_object_set_data_full(
            session.cast(),
            KEY.as_ptr(),
            Box::into_raw(hosts).cast(),
            Some(free_hosts),
        );
    }
}

/// Whether `session` holds a certificate exception for the URL host `host`.
///
/// # Safety
/// `session` is null or a live `WebKitNetworkSession` used on its owning thread.
pub(crate) unsafe fn contains(session: *mut ffi::WebKitNetworkSession, host: &str) -> bool {
    if session.is_null() {
        return false;
    }
    let Ok(host) = super::host_identity::certificate_authorization_host_from_url(host) else {
        return false;
    };
    let Ok((_, key)) = super::certificate_authorization_identity(host) else {
        return false;
    };
    // SAFETY: as in `record`.
    let hosts = unsafe { ffi::g_object_get_data(session.cast(), KEY.as_ptr()) }.cast::<Hosts>();
    // SAFETY: a non-null value under KEY is a live `Hosts` box owned by the session.
    unsafe { hosts.as_ref() }.is_some_and(|hosts| hosts.borrow().contains(&key))
}
