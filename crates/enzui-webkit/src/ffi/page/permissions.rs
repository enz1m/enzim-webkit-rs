use super::*;
use crate::site_permissions::{PermissionOrigin, SitePermission, SitePermissionRequest};
use crate::web::policy::PermissionKind;

#[derive(Default)]
pub(super) struct SitePermissions {
    enabled: bool,
    cancelling: usize,
    grants: HashMap<SitePermission, bool>,
    pending: Vec<(PageRequestId, PermissionPending)>,
}

impl SitePermissions {
    pub(super) fn has_pending(&self, id: PageRequestId) -> bool {
        self.pending.iter().any(|(found, _)| *found == id)
    }
}

struct PermissionPending {
    kind: PermissionKind,
    permission: SitePermission,
    request: *mut ffi::WebKitPermissionRequest,
    timeout: c_uint,
    generation: u64,
}
impl PermissionPending {
    fn finish(mut self, allow: bool) {
        if self.timeout != 0 {
            let timeout = std::mem::replace(&mut self.timeout, 0);
            // SAFETY: remove the owned timer before terminal native calls can reenter dispatch.
            unsafe {
                ffi::g_source_remove(timeout);
            }
        }
        let request = std::mem::replace(&mut self.request, std::ptr::null_mut());
        // SAFETY: this slot retains one live request reference, consumed exactly once.
        unsafe {
            if allow {
                ffi::webkit_permission_request_allow(request);
            } else {
                ffi::webkit_permission_request_deny(request);
            }
            ffi::g_object_unref(request.cast());
        }
    }
}
impl Drop for PermissionPending {
    fn drop(&mut self) {
        // SAFETY: only this slot owns the source and retained native request.
        unsafe {
            if self.timeout != 0 {
                ffi::g_source_remove(self.timeout);
            }
            if !self.request.is_null() {
                ffi::webkit_permission_request_deny(self.request);
                ffi::g_object_unref(self.request.cast());
            }
        }
    }
}

struct Expiry {
    hub: Weak<PageHub>,
    id: PageRequestId,
}
extern "C" fn expire(data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: the live GLib timeout owns this boxed Expiry until destroy is called.
    let expiry = unsafe { &*data.cast::<Expiry>() };
    if let Some(hub) = expiry.hub.upgrade() {
        let slot = {
            let mut state = hub.state.borrow_mut();
            state
                .site_permissions
                .pending
                .iter()
                .position(|(id, _)| *id == expiry.id)
                .map(|index| {
                    let (_, mut pending) = state.site_permissions.pending.remove(index);
                    pending.timeout = 0;
                    pending
                })
        };
        if slot.is_some() {
            drop(slot);
            hub.push(PageEvent::PermissionCancelled { id: expiry.id });
        }
    }
    ffi::G_FALSE
}
extern "C" fn destroy_expiry(data: *mut c_void) {
    // SAFETY: GLib calls the destroy callback exactly once for this owned allocation.
    drop(unsafe { Box::from_raw(data.cast::<Expiry>()) });
}

/// Copies the fork's request-time origin data; absent or opaque metadata fails closed.
///
/// # Safety
/// `object` is a live GObject, and keys are static NUL-terminated strings.
pub(crate) unsafe fn native_permission(
    object: *mut c_void,
    kind: PermissionKind,
    requesting_key: &'static std::ffi::CStr,
    top_key: &'static std::ffi::CStr,
) -> Option<SitePermission> {
    // SAFETY: object and both keys satisfy this function's native-data contract.
    let read = |key: &std::ffi::CStr| unsafe {
        let text = ffi::g_object_get_data(object, key.as_ptr()).cast::<c_char>();
        if text.is_null() {
            return None;
        }
        let value = crate::ffi::policy::scan_bounded_native_uri(text, 2048).ok()?;
        PermissionOrigin::parse(&value)
    };
    Some(SitePermission {
        kind,
        requesting_origin: read(requesting_key)?,
        top_origin: read(top_key)?,
    })
}

impl PageHub {
    pub(crate) fn inherit_site_permissions(&self, other: &PageHub) {
        let (enabled, grants, notifications_blocked) = {
            let state = other.state.borrow();
            (
                state.site_permissions.enabled,
                state.site_permissions.grants.clone(),
                state.notifications_blocked,
            )
        };
        let mut state = self.state.borrow_mut();
        state.site_permissions.enabled = enabled;
        state.site_permissions.grants = grants;
        state.notifications_blocked = notifications_blocked;
    }

    pub(crate) fn site_permissions_enabled(&self) -> bool {
        self.state.borrow().site_permissions.enabled
    }
    pub(crate) fn enable_site_permissions(&self, enabled: bool) {
        self.state.borrow_mut().site_permissions.enabled = false;
        self.cancel_site_permissions();
        let mut state = self.state.borrow_mut();
        state.site_permissions.enabled = enabled;
        state.site_permissions.grants.clear();
    }
    pub(crate) fn cancel_site_permissions(&self) -> usize {
        let pending = {
            let mut state = self.state.borrow_mut();
            state.site_permissions.cancelling += 1;
            std::mem::take(&mut state.site_permissions.pending)
        };
        let count = pending.len();
        for (id, slot) in pending {
            drop(slot);
            self.push(PageEvent::PermissionCancelled { id });
        }
        self.state.borrow_mut().site_permissions.cancelling -= 1;
        count
    }
    pub(crate) fn cancel_notification_permissions(&self) {
        let slots = {
            let mut state = self.state.borrow_mut();
            let mut cancelled = Vec::new();
            let mut index = 0;
            while index < state.site_permissions.pending.len() {
                if state.site_permissions.pending[index].1.kind == PermissionKind::Notifications {
                    cancelled.push(state.site_permissions.pending.remove(index));
                } else {
                    index += 1;
                }
            }
            cancelled
        };
        for (id, slot) in slots {
            slot.finish(false);
            self.push(PageEvent::PermissionCancelled { id });
        }
    }
    pub(crate) fn reset_notification_permissions(&self) {
        self.cancel_notification_permissions();
        self.state
            .borrow_mut()
            .site_permissions
            .grants
            .retain(|permission, _| permission.kind != PermissionKind::Notifications);
        self.release_notifications();
    }
    pub(crate) fn set_notifications_enabled(&self, enabled: bool) {
        self.state.borrow_mut().notifications_blocked = !enabled;
        if !enabled {
            self.cancel_notification_permissions();
            self.release_notifications();
        }
    }
    pub(crate) fn set_site_permission(&self, permission: SitePermission, allowed: bool) -> bool {
        let supported = matches!(
            permission.kind,
            PermissionKind::Camera | PermissionKind::Microphone | PermissionKind::Geolocation
        ) || permission.kind == PermissionKind::Notifications
            && permission.requesting_origin == permission.top_origin;
        if !supported {
            return false;
        }
        let mut state = self.state.borrow_mut();
        if !state.site_permissions.enabled {
            return false;
        }
        let grants = &mut state.site_permissions.grants;
        if grants.len() >= 128 && !grants.contains_key(&permission) {
            return false;
        }
        grants.insert(permission, allowed);
        true
    }
    pub(crate) fn site_permission_grant(&self, permission: &SitePermission) -> Option<bool> {
        let state = self.state.borrow();
        if permission.kind == PermissionKind::Notifications
            && (state.notifications_blocked
                || permission.requesting_origin != permission.top_origin)
        {
            return Some(false);
        }
        let grants = &state.site_permissions.grants;
        if permission.kind == PermissionKind::CameraAndMicrophone {
            let camera = grants
                .get(&SitePermission {
                    kind: PermissionKind::Camera,
                    ..permission.clone()
                })
                .copied();
            let microphone = grants
                .get(&SitePermission {
                    kind: PermissionKind::Microphone,
                    ..permission.clone()
                })
                .copied();
            match (camera, microphone) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            }
        } else {
            grants.get(permission).copied()
        }
    }
    pub(crate) fn handle_site_permission(
        self: &Rc<Self>,
        request: *mut ffi::WebKitPermissionRequest,
        kind: PermissionKind,
    ) -> bool {
        let globally_blocked =
            kind == PermissionKind::Notifications && self.state.borrow().notifications_blocked;
        if globally_blocked || self.state.borrow().site_permissions.cancelling != 0 {
            // SAFETY: the live callback request accepts one terminal denial before dispatch returns.
            unsafe {
                ffi::webkit_permission_request_deny(request);
            }
            return true;
        }
        if !self.site_permissions_enabled() {
            return false;
        }
        // SAFETY: the policy callback supplies the live request GObject and fixed fork metadata keys.
        let context = unsafe {
            native_permission(
                request.cast(),
                kind,
                c"enzui-permission-requesting-origin-v1",
                c"enzui-permission-top-origin-v1",
            )
        };
        let known = match kind {
            PermissionKind::Camera
            | PermissionKind::Microphone
            | PermissionKind::CameraAndMicrophone
            | PermissionKind::ScreenCapture
            | PermissionKind::Geolocation => true,
            PermissionKind::Notifications => context
                .as_ref()
                .is_some_and(|permission| permission.requesting_origin == permission.top_origin),
            _ => false,
        };
        let context = context.filter(|_| known);
        let decision = context.as_ref().and_then(|p| self.site_permission_grant(p));
        if context.is_none()
            || decision.is_some()
            || self.state.borrow().site_permissions.pending.len() >= 4
        {
            // SAFETY: the callback owns a live request; exactly one terminal action is selected.
            unsafe {
                if context.is_some() && decision == Some(true) {
                    ffi::webkit_permission_request_allow(request);
                } else {
                    ffi::webkit_permission_request_deny(request);
                }
            }
            return true;
        }
        let id = self.mint();
        let generation = self.state.borrow().load_generation;
        let expiry = Box::into_raw(Box::new(Expiry {
            hub: Rc::downgrade(self),
            id,
        }));
        // SAFETY: the timeout owns Expiry through its destroy callback, and the pending slot retains the request.
        let timeout = unsafe {
            ffi::g_object_ref(request.cast());
            ffi::g_timeout_add_full(0, 30_000, Some(expire), expiry.cast(), Some(destroy_expiry))
        };
        if timeout == 0 {
            // SAFETY: GLib owns the timer data even when attachment fails; release only the retained request.
            unsafe {
                ffi::webkit_permission_request_deny(request);
                ffi::g_object_unref(request.cast());
            }
            return true;
        }
        self.state.borrow_mut().site_permissions.pending.push((
            id,
            PermissionPending {
                kind,
                permission: context
                    .as_ref()
                    .expect("validated permission context")
                    .clone(),
                request,
                timeout,
                generation,
            },
        ));
        self.push(PageEvent::PermissionRequested(SitePermissionRequest {
            id,
            permission: context.unwrap(),
        }));
        true
    }
    pub(crate) fn answer_site_permission(
        &self,
        id: PageRequestId,
        allowed: bool,
    ) -> Result<(), AnswerError> {
        let (slot, generation) = {
            let mut state = self.state.borrow_mut();
            let index = state
                .site_permissions
                .pending
                .iter()
                .position(|(found, _)| *found == id)
                .ok_or(AnswerError::Unknown)?;
            (
                state.site_permissions.pending.remove(index).1,
                state.load_generation,
            )
        };
        if slot.generation != generation {
            drop(slot);
            return Err(AnswerError::Unknown);
        }
        if slot.kind == PermissionKind::Notifications {
            self.set_site_permission(slot.permission.clone(), allowed);
        }
        slot.finish(allowed);
        Ok(())
    }
}

#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

fn media_history_api() -> Option<unsafe extern "C" fn(*mut ffi::WebKitWebView, ffi::GBoolean)> {
    type Clear = unsafe extern "C" fn(*mut ffi::WebKitWebView, ffi::GBoolean);
    static API: std::sync::OnceLock<Option<Clear>> = std::sync::OnceLock::new();
    let api = API.get_or_init(|| {
        // SAFETY: the fixed fork symbol is searched in already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                std::ptr::null_mut(),
                c"webkit_web_view_enzui_clear_media_permission_history".as_ptr(),
            )
        };
        if symbol.is_null() {
            None
        } else {
            // SAFETY: the reviewed fork symbol has this exact owner-thread C ABI.
            Some(unsafe { std::mem::transmute::<*mut c_void, Clear>(symbol) })
        }
    });
    *api
}
pub(crate) fn has_media_history_api() -> bool {
    media_history_api().is_some()
}
pub(crate) fn clear_media_permission_history(view: *mut ffi::WebKitWebView, camera: bool) -> bool {
    if let Some(clear) = media_history_api() {
        // SAFETY: the session caller owns this view on its native owner thread.
        unsafe { clear(view, i32::from(camera)) };
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests;
