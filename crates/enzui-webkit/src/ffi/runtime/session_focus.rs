//! Handing keyboard focus back to the host when Tab or Shift+Tab moves past
//! the last or first focusable element of the page, as a browser moves focus
//! from the page to its own controls.
use super::*;
use crate::ffi::page::PageHub;

type TakeFocus =
    unsafe extern "C" fn(*mut ffi::WebKitWebView, ffi::GBoolean, *mut c_void) -> ffi::GBoolean;
type SetTakeFocus = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    Option<TakeFocus>,
    *mut c_void,
    Option<unsafe extern "C" fn(*mut c_void)>,
);

#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

fn take_focus_api() -> Option<SetTakeFocus> {
    static API: std::sync::OnceLock<Option<SetTakeFocus>> = std::sync::OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: a fixed fork symbol is resolved from already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                ptr::null_mut(),
                c"webkit_web_view_enzui_set_take_focus_callback_v1".as_ptr(),
            )
        };
        // SAFETY: the function uses the reviewed fork's exact C ABI.
        (!symbol.is_null())
            .then(|| unsafe { std::mem::transmute::<*mut c_void, SetTakeFocus>(symbol) })
    })
}

unsafe extern "C" fn on_take_focus(
    _view: *mut ffi::WebKitWebView,
    backward: ffi::GBoolean,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: `data` is the page hub reference the view holds until it drops
    // the callback; WebKit calls this on the owner thread.
    let hub = unsafe { &*data.cast::<PageHub>() };
    hub.push(crate::page::PageEvent::FocusLeftPage {
        backward: backward != ffi::G_FALSE,
        load: hub.load_state().0,
    });
    ffi::G_TRUE
}

unsafe extern "C" fn release_hub(data: *mut c_void) {
    // SAFETY: the reference was leaked for this callback in `set_focus_handoff`.
    drop(unsafe { std::rc::Rc::from_raw(data.cast::<PageHub>()) });
}

impl WebSession {
    /// Whether focus leaving the page goes to the host.
    ///
    /// When enabled, Tab past the page's last focusable element or Shift+Tab
    /// past its first takes focus out of the page and reports
    /// [`PageEvent::FocusLeftPage`] with the direction and the page's
    /// [`Self::load_generation`]; the host then moves focus to its own
    /// controls. Disabled, focus stays in the page as WebKit keeps it.
    /// Returns `false` when enabling on a runtime without it.
    pub fn set_focus_handoff(&self, enabled: bool) -> bool {
        let Some(set) = take_focus_api() else {
            return !enabled;
        };
        // SAFETY: a live view on its owner thread; the hub reference stays
        // valid until WebKit calls `release_hub`, when the callback is
        // replaced or the view finalizes.
        unsafe {
            if enabled {
                let hub = std::rc::Rc::into_raw(std::rc::Rc::clone(&self.page_hub));
                set(
                    self.web_view,
                    Some(on_take_focus),
                    hub.cast_mut().cast(),
                    Some(release_hub),
                );
            } else {
                set(self.web_view, None, ptr::null_mut(), None);
            }
        }
        true
    }

    /// The number of loads this page has started; events carrying it, such
    /// as [`PageEvent::FocusLeftPage`], belong to the document current when
    /// it still matches.
    #[must_use]
    pub fn load_generation(&self) -> u64 {
        self.page_hub.load_state().0
    }
}
