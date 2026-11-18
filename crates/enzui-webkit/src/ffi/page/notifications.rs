//! Website notifications the host shows: their native origin, and the click
//! and close lifecycle between the page and the host's desktop entry.

use super::*;
use crate::site_permissions::PermissionOrigin;

/// The most notifications one session keeps for click and close relay; the
/// oldest is closed for a newer one.
pub const MAX_SHOWN_NOTIFICATIONS: usize = 32;

/// A notification the host shows, held until it closes.
pub(super) struct ShownNotification {
    id: u64,
    notification: *mut WebKitNotification,
    handler: u64,
    origin: Option<PermissionOrigin>,
}

impl Drop for ShownNotification {
    fn drop(&mut self) {
        // SAFETY: the handler was connected on this notification, which this
        // entry holds a reference to.
        unsafe {
            ffi::g_signal_handler_disconnect(self.notification.cast(), self.handler);
            ffi::g_object_unref(self.notification.cast());
        }
    }
}

struct ClosedData {
    hub: Weak<PageHub>,
    id: u64,
}

extern "C" fn on_closed(_notification: *mut WebKitNotification, data: *mut c_void) {
    // SAFETY: the handler's data box lives until the handler is disconnected.
    let data = unsafe { &*data.cast::<ClosedData>() };
    if let Some(hub) = data.hub.upgrade() {
        let removed = {
            let mut state = hub.state.borrow_mut();
            let index = state
                .notifications
                .iter()
                .position(|shown| shown.id == data.id);
            index.map(|index| state.notifications.remove(index))
        };
        hub.push(PageEvent::NotificationClosed { id: data.id });
        drop(removed);
    }
}

extern "C" fn free_closed_data(data: *mut c_void, _closure: *mut c_void) {
    // SAFETY: the box was leaked for this handler in `keep`.
    drop(unsafe { Box::from_raw(data.cast::<ClosedData>()) });
}

type NotificationOrigin = unsafe extern "C" fn(*mut WebKitNotification) -> *const c_char;

/// The notification's origin from WebKit's own record, on a runtime with it.
///
/// # Safety
/// The caller retains the live native notification throughout the lookup.
pub(super) unsafe fn native_origin(
    notification: *mut WebKitNotification,
) -> Option<PermissionOrigin> {
    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    }
    static API: std::sync::OnceLock<Option<NotificationOrigin>> = std::sync::OnceLock::new();
    let api = (*API.get_or_init(|| {
        // SAFETY: a fixed fork symbol is resolved from already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                core::ptr::null_mut(),
                c"webkit_notification_enzui_get_origin_v1".as_ptr(),
            )
        };
        // SAFETY: the function uses the reviewed fork's exact C ABI.
        (!symbol.is_null())
            .then(|| unsafe { std::mem::transmute::<*mut c_void, NotificationOrigin>(symbol) })
    }))?;
    // SAFETY: the notification is live for the caller; the string it returns
    // is owned by the notification and copied here.
    let text = unsafe { api(notification) };
    if text.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string owned by the live notification.
    let value = unsafe { crate::ffi::policy::scan_bounded_native_uri(text, 2048) }.ok()?;
    PermissionOrigin::parse(&value)
}

impl PageHub {
    pub(super) fn keep_notification(
        self: &Rc<Self>,
        notification: *mut WebKitNotification,
        id: u64,
        origin: Option<PermissionOrigin>,
    ) {
        let data = Box::into_raw(Box::new(ClosedData {
            hub: Rc::downgrade(self),
            id,
        }));
        // SAFETY: the notification is live; the handler matches the `closed`
        // signal and its data box is freed when the handler goes.
        let handler = unsafe {
            ffi::g_object_ref(notification.cast());
            ffi::g_signal_connect_data(
                notification.cast(),
                c"closed".as_ptr(),
                std::mem::transmute::<
                    extern "C" fn(*mut WebKitNotification, *mut c_void),
                    extern "C" fn(),
                >(on_closed),
                data.cast(),
                free_closed_data as *mut c_void,
                0,
            )
        };
        let evicted = {
            let mut state = self.state.borrow_mut();
            let evicted = (state.notifications.len() >= MAX_SHOWN_NOTIFICATIONS)
                .then(|| state.notifications.remove(0));
            state.notifications.push(ShownNotification {
                id,
                notification,
                handler,
                origin,
            });
            evicted
        };
        if let Some(evicted) = evicted {
            // SAFETY: the entry holds a reference to the live notification.
            unsafe { webkit_notification_close(evicted.notification) };
        }
    }

    fn shown_notification(&self, id: u64) -> Option<*mut WebKitNotification> {
        self.state
            .borrow()
            .notifications
            .iter()
            .find(|shown| shown.id == id)
            .map(|shown| shown.notification)
    }

    pub(crate) fn click_notification(&self, id: u64) -> bool {
        let Some(notification) = self.shown_notification(id) else {
            return false;
        };
        // SAFETY: the hub holds a reference to the live notification.
        unsafe {
            ffi::g_object_ref(notification.cast());
            webkit_notification_clicked(notification);
            ffi::g_object_unref(notification.cast());
        }
        true
    }

    pub(crate) fn close_notification(&self, id: u64) -> bool {
        let Some(notification) = self.shown_notification(id) else {
            return false;
        };
        // SAFETY: the hub holds a reference to the live notification; its
        // `closed` handler removes the entry.
        unsafe {
            ffi::g_object_ref(notification.cast());
            webkit_notification_close(notification);
            ffi::g_object_unref(notification.cast());
        }
        true
    }

    pub(crate) fn release_notifications(&self) {
        let shown = std::mem::take(&mut self.state.borrow_mut().notifications);
        for shown in shown {
            // SAFETY: each slot retains this notification throughout the native close callback.
            unsafe { webkit_notification_close(shown.notification) };
        }
    }
    pub(crate) fn close_notifications_for_origin(&self, origin: &PermissionOrigin) {
        let ids = self
            .state
            .borrow()
            .notifications
            .iter()
            .filter(|shown| shown.origin.as_ref() == Some(origin))
            .map(|shown| shown.id)
            .collect::<Vec<_>>();
        for id in ids {
            self.close_notification(id);
        }
    }
}
