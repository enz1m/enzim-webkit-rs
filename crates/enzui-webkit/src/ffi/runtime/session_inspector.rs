//! The local Web Inspector frontend as a second routed view of a session.
//!
//! WPE creates the frontend as its own `WPEView` on the inspected view's
//! display, with a sandboxed process pool and a dedicated website-data store.
//! Nothing listens on a socket; the remote inspector server stays off. The host
//! binds the frontend to a [`ViewId`] of its own, then uses the session's usual
//! frame, input and resize calls with that id.
use super::*;
use crate::web::{ViewId, ViewRouter};
use std::sync::OnceLock;

type SetVisible = unsafe extern "C" fn(*mut ffi::WebKitWebView, ffi::GBoolean) -> ffi::GBoolean;
type GetView = unsafe extern "C" fn(*mut ffi::WebKitWebView) -> *mut ffi::WPEView;
struct Api {
    set_visible: SetVisible,
    get_view: GetView,
}
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: fixed fork symbols are resolved from already loaded native libraries.
        let (set_visible, get_view) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_set_inspector_visible_v1".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_get_inspector_view_v1".as_ptr(),
                ),
            )
        };
        if set_visible.is_null() || get_view.is_null() {
            return None;
        }
        // SAFETY: these functions use the reviewed fork's exact C ABI.
        Some(unsafe {
            Api {
                set_visible: std::mem::transmute::<*mut c_void, SetVisible>(set_visible),
                get_view: std::mem::transmute::<*mut c_void, GetView>(get_view),
            }
        })
    })
    .as_ref()
}

/// Why an inspector request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InspectorError {
    /// The runtime predates the embeddable inspector.
    Unsupported,
    /// [`crate::page::WebSettings::developer_extras`] is off.
    DeveloperExtrasDisabled,
    /// No frontend is open yet; pump after [`WebSession::set_inspector_open`].
    NotOpen,
    /// The id is not live in the router, or is the page's own view.
    ViewNotLive,
}

impl std::fmt::Display for InspectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "the runtime has no embeddable inspector",
            Self::DeveloperExtrasDisabled => "developer extras are disabled",
            Self::NotOpen => "the inspector frontend is not open",
            Self::ViewNotLive => "the inspector view id is not live",
        })
    }
}

impl std::error::Error for InspectorError {}

/// The bound frontend: a strong reference keeps its address from being reused
/// while the session compares it against the native current view.
pub(crate) struct InspectorFrontend {
    pub(crate) wpe_view: *mut ffi::WPEView,
    pub(crate) view: ViewId,
    pub(crate) presentation: crate::ffi::presentation::PresentationBinding,
}

impl Drop for InspectorFrontend {
    fn drop(&mut self) {
        // SAFETY: the reference was taken in `bind_inspector`; the binding has
        // no other owner of this reference.
        unsafe { ffi::g_object_unref(self.wpe_view.cast()) };
    }
}

impl WebSession {
    /// Whether this runtime can present the local inspector to the host.
    #[must_use]
    pub fn supports_inspector(&self) -> bool {
        api().is_some()
    }

    /// Open or close the local inspector, returning whether it is open now.
    ///
    /// Opening is asynchronous: the frontend appears after the inspected page
    /// answers, so pump until [`Self::bind_inspector`] stops returning
    /// [`InspectorError::NotOpen`]. Closing releases the frontend and stops
    /// the page's instrumentation; a bound frontend reports
    /// [`crate::page::PageEvent::InspectorClosed`].
    ///
    /// # Errors
    /// [`InspectorError::Unsupported`] or [`InspectorError::DeveloperExtrasDisabled`].
    pub fn set_inspector_open(&self, open: bool) -> Result<bool, InspectorError> {
        let api = api().ok_or(InspectorError::Unsupported)?;
        if open && !self.developer_extras_enabled() {
            return Err(InspectorError::DeveloperExtrasDisabled);
        }
        // SAFETY: the session's view is live on its owning thread.
        let visible = unsafe {
            (api.set_visible)(self.web_view, if open { ffi::G_TRUE } else { ffi::G_FALSE })
        } != ffi::G_FALSE;
        if !open {
            self.check_inspector();
        }
        Ok(visible)
    }

    /// Bind the open frontend to `view`, a host id distinct from the page's.
    ///
    /// The frontend's frames then arrive through [`Self::take_gpu_frame`] and
    /// [`Self::take_shared_gpu_frame`], its input through
    /// [`Self::forward_input`] and its size through [`Self::resize_inspector`],
    /// all with `view`. Binding again moves the frontend to the new id.
    ///
    /// # Errors
    /// [`InspectorError::Unsupported`], [`InspectorError::NotOpen`] or
    /// [`InspectorError::ViewNotLive`].
    pub fn bind_inspector(&self, router: &ViewRouter, view: ViewId) -> Result<(), InspectorError> {
        let api = api().ok_or(InspectorError::Unsupported)?;
        if !router.accepts(view) || self.bound_view == Some(view) {
            return Err(InspectorError::ViewNotLive);
        }
        // SAFETY: the session's view is live; the returned view is borrowed.
        let current = unsafe { (api.get_view)(self.web_view) };
        if current.is_null() {
            self.inspector.replace(None);
            return Err(InspectorError::NotOpen);
        }
        // WebKit attaches the frontend to its toplevel once the frontend window
        // exists; until then it cannot be sized or presented.
        // SAFETY: `current` is live; the toplevel is only tested for presence.
        if unsafe { ffi::wpe_view_get_toplevel(current) }.is_null() {
            return Err(InspectorError::NotOpen);
        }
        let mut slot = self.inspector.borrow_mut();
        if let Some(frontend) = slot.as_mut().filter(|f| f.wpe_view == current) {
            frontend.view = view;
            frontend.presentation.set_view(view);
            return Ok(());
        }
        drop(slot.take());
        // SAFETY: `current` is the live frontend view; the reference keeps it
        // alive until the binding drops.
        unsafe { ffi::g_object_ref(current.cast()) };
        *slot = Some(InspectorFrontend {
            wpe_view: current,
            view,
            // SAFETY: the frontend view is live and owned by this thread's display.
            presentation: unsafe {
                crate::ffi::presentation::PresentationBinding::new(current, Some(view))
            },
        });
        Ok(())
    }

    /// Inspect the element at view point `at`, as a context menu's Inspect
    /// Element does: the inspector opens if needed and selects that node.
    /// Pump, then bind the frontend as after [`Self::set_inspector_open`].
    ///
    /// # Errors
    /// [`InspectorError::Unsupported`] or [`InspectorError::DeveloperExtrasDisabled`].
    pub fn inspect_element_at(&self, at: crate::input::ViewPoint) -> Result<(), InspectorError> {
        // WebKit ignores a page's own request to open the inspector, so open it
        // here as the context menu does; the page then selects the node.
        self.set_inspector_open(true)?;
        // View points are logical pixels; the page hit-tests whole pixels.
        let (x, y) = (at.x.round() as i32, at.y.round() as i32);
        // SAFETY: the tuple consumes its floating children and the message
        // consumes the floating tuple; sending consumes the floating message.
        unsafe {
            let children = [ffi::g_variant_new_int32(x), ffi::g_variant_new_int32(y)];
            let point = ffi::g_variant_new_tuple(children.as_ptr(), children.len());
            let message = ffi::webkit_user_message_new(c"enzui-inspect-element-v1".as_ptr(), point);
            if !message.is_null() {
                ffi::webkit_web_view_send_message_to_page(
                    self.web_view,
                    message,
                    ptr::null_mut(),
                    None,
                    ptr::null_mut(),
                );
            }
        }
        Ok(())
    }

    /// The host id the open frontend is bound to, if any.
    #[must_use]
    pub fn inspector_view(&self) -> Option<ViewId> {
        self.check_inspector();
        self.inspector.borrow().as_ref().map(|f| f.view)
    }

    /// Resize the bound frontend.
    ///
    /// # Errors
    /// [`ViewportResizeError::ViewNotBound`] without a bound frontend, or the
    /// same ownership and backend errors as [`Self::resize_viewport`].
    pub fn resize_inspector(
        &self,
        router: &ViewRouter,
        view: ViewId,
        size: crate::viewport::ViewportSize,
    ) -> Result<ViewportResize, ViewportResizeError> {
        let wpe_view = self
            .inspector_target(view)
            .ok_or(ViewportResizeError::ViewNotBound)?;
        if !router.accepts(view) {
            return Err(ViewportResizeError::ViewNotLive { view });
        }
        // SAFETY: the bound frontend view is live; its toplevel is borrowed.
        unsafe { resize_toplevel(wpe_view, size) }
    }

    /// The live frontend view bound to `view`, after confirming it is still
    /// the native current frontend.
    pub(crate) fn inspector_target(&self, view: ViewId) -> Option<*mut ffi::WPEView> {
        self.check_inspector();
        self.inspector
            .borrow()
            .as_ref()
            .filter(|f| f.view == view)
            .map(|f| f.wpe_view)
    }

    /// Release a frontend the engine has closed and report it to the host.
    pub(super) fn check_inspector(&self) {
        let Some(api) = api() else { return };
        let stale = {
            let slot = self.inspector.borrow();
            let Some(frontend) = slot.as_ref() else {
                return;
            };
            // SAFETY: the session's view is live; the returned view is only compared.
            unsafe { (api.get_view)(self.web_view) != frontend.wpe_view }
        };
        if stale && let Some(frontend) = self.inspector.take() {
            self.page_hub.push(crate::page::PageEvent::InspectorClosed {
                view: frontend.view,
            });
        }
    }

    fn developer_extras_enabled(&self) -> bool {
        // SAFETY: the view and its settings object are live and borrowed.
        unsafe {
            crate::ffi::page::sys::webkit_settings_get_enable_developer_extras(
                crate::ffi::page::sys::webkit_web_view_get_settings(self.web_view.cast()),
            ) != ffi::G_FALSE
        }
    }
}

/// Resize `wpe_view`'s toplevel, reporting a size it already has as unchanged.
///
/// # Safety
/// `wpe_view` must be live on this thread.
pub(super) unsafe fn resize_toplevel(
    wpe_view: *mut ffi::WPEView,
    size: crate::viewport::ViewportSize,
) -> Result<ViewportResize, ViewportResizeError> {
    // SAFETY: caller contract; the toplevel is borrowed for this call.
    let toplevel = unsafe { ffi::wpe_view_get_toplevel(wpe_view) };
    if toplevel.is_null() {
        return Err(ViewportResizeError::NoToplevel);
    }
    let (mut width, mut height): (c_int, c_int) = (0, 0);
    // SAFETY: live toplevel; the out-parameters are stack locals.
    unsafe { ffi::wpe_toplevel_get_size(toplevel, &mut width, &mut height) };
    if width == size.width() && height == size.height() {
        return Ok(ViewportResize::Unchanged);
    }
    // SAFETY: live toplevel; `ViewportSize` guarantees positive gint dimensions.
    if unsafe { ffi::wpe_toplevel_resize(toplevel, size.width(), size.height()) } != 0 {
        Ok(ViewportResize::Requested)
    } else {
        Err(ViewportResizeError::Unsupported)
    }
}
