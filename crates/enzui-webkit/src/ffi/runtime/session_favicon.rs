use super::{WebSession, ffi};
use crate::favicon::{FaviconError, OwnedFavicon};
use crate::ffi::native_task::{
    NativeTask, NativeTaskCompletion, NativeTaskError, NativeTaskLimiter,
};
use std::ffi::{CStr, c_char, c_void};
use std::ptr;
use std::rc::{Rc, Weak};
use std::sync::OnceLock;
use std::time::Duration;

type SetEnabled = unsafe extern "C" fn(*mut c_void, ffi::GBoolean);
type GetDatabase = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetIcons = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    extern "C" fn(*mut c_void, *mut ffi::GAsyncResult, *mut c_void),
    *mut c_void,
);
type Finish =
    unsafe extern "C" fn(*mut c_void, *mut ffi::GAsyncResult, *mut *mut ffi::GError) -> *mut c_void;
type Length = unsafe extern "C" fn(*mut c_void) -> usize;
type Get = unsafe extern "C" fn(*mut c_void, usize) -> *mut ffi::WebKitImage;
type Unref = unsafe extern "C" fn(*mut c_void);
struct Api {
    enable: SetEnabled,
    database: GetDatabase,
    get: GetIcons,
    finish: Finish,
    length: Length,
    image: Get,
    unref: Unref,
}
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        let names = [
            c"webkit_website_data_manager_set_favicons_enabled",
            c"webkit_website_data_manager_get_favicon_database",
            c"webkit_favicon_database_get_page_icons",
            c"webkit_favicon_database_get_page_icons_finish",
            c"webkit_image_list_get_length",
            c"webkit_image_list_get",
            c"webkit_image_list_unref",
        ];
        // SAFETY: RTLD_DEFAULT searches already loaded modules with NUL-terminated names.
        let functions = names.map(|name| unsafe { dlsym(ptr::null_mut(), name.as_ptr()) });
        if functions.iter().any(|p| p.is_null()) {
            return None;
        }
        // SAFETY: these signatures match WPE's public 2.54 icon declarations.
        Some(unsafe {
            Api {
                enable: std::mem::transmute::<*mut c_void, SetEnabled>(functions[0]),
                database: std::mem::transmute::<*mut c_void, GetDatabase>(functions[1]),
                get: std::mem::transmute::<*mut c_void, GetIcons>(functions[2]),
                finish: std::mem::transmute::<*mut c_void, Finish>(functions[3]),
                length: std::mem::transmute::<*mut c_void, Length>(functions[4]),
                image: std::mem::transmute::<*mut c_void, Get>(functions[5]),
                unref: std::mem::transmute::<*mut c_void, Unref>(functions[6]),
            }
        })
    })
    .as_ref()
}
pub(super) fn clear_favicon_database(network: *mut ffi::WebKitNetworkSession) {
    let Some(api) = api() else { return };
    // SAFETY: the runtime lookup uses the public WPE signature, and the
    // network session is live on its owner thread for the database access.
    unsafe {
        let clear = dlsym(ptr::null_mut(), c"webkit_favicon_database_clear".as_ptr());
        if clear.is_null() {
            return;
        }
        let manager =
            crate::ffi::page::sys::webkit_network_session_get_website_data_manager(network);
        let database = (api.database)(manager.cast());
        if !database.is_null() {
            let clear =
                std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void)>(clear);
            clear(database);
        }
    }
}

fn task_error(error: NativeTaskError) -> FaviconError {
    match error {
        NativeTaskError::Cancelled => FaviconError::Cancelled,
        NativeTaskError::TimedOut => FaviconError::TimedOut,
        NativeTaskError::Busy => FaviconError::Busy,
        NativeTaskError::WrongThread => FaviconError::WrongThread,
        NativeTaskError::InvalidInput(message) => FaviconError::Native(message.into()),
        NativeTaskError::Native(message) => FaviconError::Native(message),
    }
}
thread_local! { static LIMITER: NativeTaskLimiter = NativeTaskLimiter::new(2); }

/// An owner-thread native lookup; drive the normal event loop and poll for its result.
/// Drop requests cancellation and retains native ownership until actual completion.
pub struct FaviconTask(NativeTask<Result<OwnedFavicon, FaviconError>>);
impl FaviconTask {
    /// Take the terminal result once without blocking or pumping a nested event loop.
    pub fn take_result(&self) -> Option<Result<OwnedFavicon, FaviconError>> {
        self.0
            .take_result()
            .map(|r| r.map_err(task_error).and_then(|r| r))
    }
    /// Request cancellation; native callback state remains retained until teardown.
    pub fn cancel(&self) {
        self.0.cancel();
    }
    /// Observe completion or deadline without consuming the result.
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}
struct Request {
    completion: Option<NativeTaskCompletion<Result<OwnedFavicon, FaviconError>>>,
    view: *mut ffi::WebKitWebView,
    resource: *mut c_void,
    hub: Weak<crate::ffi::page::PageHub>,
    load_generation: u64,
    navigation_intent: u64,
    lifetime: Weak<()>,
    identity: Rc<std::cell::Cell<Option<crate::web::ViewId>>>,
    view_identity: Option<crate::web::ViewId>,
    document: String,
    /// Earlier URLs of the same document to ask for next, oldest last.
    fallbacks: Vec<std::ffi::CString>,
    _network: Option<Rc<crate::ffi::profile::NetworkSession>>,
}
impl Request {
    fn current(&self) -> bool {
        let logical = self.lifetime.upgrade().is_some()
            && self.identity.get() == self.view_identity
            && self.hub.upgrade().is_some_and(|h| {
                h.load_state().0 == self.load_generation
                    && h.navigation_intent() == self.navigation_intent
            });
        let active = self
            .completion
            .as_ref()
            .expect("active favicon request")
            .is_active();
        // SAFETY: the request retains this native view and original resource.
        logical
            && active
            && unsafe { webkit_web_view_get_main_resource(self.view) == self.resource }
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        // SAFETY: owned references are released only after the native task teardown.
        unsafe {
            ffi::g_object_unref(self.resource);
            ffi::g_object_unref(self.view.cast());
        }
    }
}
struct Completed {
    request: Box<Request>,
    result: Result<OwnedFavicon, FaviconError>,
}
extern "C" fn complete_later(data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: one source owns this completion allocation.
    let mut done = unsafe { Box::from_raw(data.cast::<Completed>()) };
    let outcome = if done.request.current() {
        done.result
    } else {
        Err(FaviconError::StaleDocument)
    };
    done.request
        .completion
        .take()
        .expect("favicon completion")
        .complete(Ok(outcome));
    ffi::G_FALSE
}
extern "C" fn finished(database: *mut c_void, result: *mut ffi::GAsyncResult, data: *mut c_void) {
    // SAFETY: this unique request was passed to exactly one native callback.
    let mut request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let api = api().expect("retained native icon API");
    let mut error = ptr::null_mut();
    // SAFETY: callback source/result match this finish function.
    let images = unsafe { (api.finish)(database, result, &mut error) };
    let outcome = if !error.is_null() {
        // SAFETY: finish transfers one native error, consumed without exposing URI diagnostics.
        unsafe { ffi::g_error_free(error) };
        Err(FaviconError::NotFound)
    } else if !request.current() {
        Err(FaviconError::StaleDocument)
    } else {
        read_image(api, images, &request.document, request.view_identity)
    };
    if !images.is_null() {
        // SAFETY: finish transfers exactly one icon-list reference.
        unsafe { (api.unref)(images) };
    }
    // WebKit files icons under the page URL current when they loaded; a
    // later same-document replaceState leaves them under an earlier URL of
    // this same live document.
    if outcome == Err(FaviconError::NotFound)
        && request.current()
        && let Some(next) = request.fallbacks.pop()
    {
        let cancellable = request
            .completion
            .as_ref()
            .expect("favicon request")
            .cancellable();
        // SAFETY: the database is this callback's live source; the request
        // moves to exactly one next callback, and native copies the URI.
        unsafe {
            (api.get)(
                database,
                next.as_ptr(),
                cancellable,
                finished,
                Box::into_raw(request).cast(),
            );
        }
        return;
    }
    let completed = Box::new(Completed {
        request,
        result: outcome,
    });
    // Releasing the last view/profile inside GTask's callback invalidates its later teardown.
    // SAFETY: this one-shot source owns the box until its next dispatch.
    unsafe { ffi::g_timeout_add(0, complete_later, Box::into_raw(completed).cast()) };
}
fn read_image(
    api: &Api,
    images: *mut c_void,
    document: &str,
    view_identity: Option<crate::web::ViewId>,
) -> Result<OwnedFavicon, FaviconError> {
    if images.is_null() {
        return Err(FaviconError::NotFound);
    }
    // SAFETY: this callback owns the live image list through all borrowed image access.
    let length = unsafe { (api.length)(images) };
    if length == 0 {
        return Err(FaviconError::NotFound);
    }
    if length > 32 {
        return Err(FaviconError::ImageTooLarge);
    }
    // Native image order and source provenance travel together, including rejected candidates.
    // SAFETY: the bounded final index belongs to the retained native list.
    let image = unsafe { (api.image)(images, length - 1) };
    if image.is_null() {
        return Err(FaviconError::NotFound);
    }
    // SAFETY: native getters borrow this live image and its versioned source metadata.
    let (width, height, stride, source) = unsafe {
        (
            ffi::webkit_image_get_width(image),
            ffi::webkit_image_get_height(image),
            ffi::webkit_image_get_stride(image),
            ffi::g_object_get_data(image.cast(), c"enzui-favicon-source-v1".as_ptr())
                .cast::<c_char>(),
        )
    };
    if width <= 0
        || height <= 0
        || width > 512
        || height > 512
        || stride < width as u32 * 4
        || stride > 512 * 4
    {
        return Err(FaviconError::ImageTooLarge);
    }
    if source.is_null() {
        return Err(FaviconError::UnsupportedRuntime);
    }
    // SAFETY: native owns a NUL-terminated URL for the image lifetime; length is checked before copying.
    let source = unsafe { CStr::from_ptr(source) };
    if source.to_bytes().len() > 8192 {
        return Err(FaviconError::ImageTooLarge);
    }
    let source = source.to_str().map_err(|_| FaviconError::NotFound)?;
    let _ = crate::web::DestinationPolicy::trusted_local()
        .screen_request(source)
        .map_err(|_| FaviconError::NotFound)?;
    // SAFETY: the retained image owns this borrowed immutable pixel buffer.
    let bytes = unsafe { ffi::webkit_image_as_bytes(image) };
    if bytes.is_null() {
        return Err(FaviconError::NotFound);
    }
    let mut size = 0;
    // SAFETY: the retained image keeps GBytes storage alive until this function returns.
    let data = unsafe { ffi::g_bytes_get_data(bytes, &mut size) }.cast::<u8>();
    (|| {
        if data.is_null()
            || size < stride as usize * (height as usize - 1) + width as usize * 4
            || size > 512 * 512 * 4
        {
            return Err(FaviconError::ImageTooLarge);
        }
        // SAFETY: the exact byte range is borrowed from the retained immutable GBytes.
        let pixels = unsafe { std::slice::from_raw_parts(data, size) };
        let mut rgba = vec![0_u8; 32 * 32 * 4];
        for y in 0..32 {
            for x in 0..32 {
                let offset =
                    (y * height as usize / 32) * stride as usize + (x * width as usize / 32) * 4;
                let alpha = pixels[offset + 3] as u32;
                let target = (y * 32 + x) * 4;
                for (channel, native) in [2, 1, 0].into_iter().enumerate() {
                    rgba[target + channel] = (pixels[offset + native] as u32 * 255)
                        .checked_div(alpha)
                        .unwrap_or(0)
                        .min(255) as u8;
                }
                rgba[target + 3] = alpha as u8;
            }
        }
        let mut output = Vec::new();
        let mut encoder = png::Encoder::new(&mut output, 32, 32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .and_then(|mut writer| writer.write_image_data(&rgba))
            .map_err(|_| FaviconError::Native("PNG encoding failed".into()))?;
        if output.len() > 16 * 1024 {
            return Err(FaviconError::ImageTooLarge);
        }
        Ok(OwnedFavicon {
            view: view_identity,
            document_uri: document.to_owned(),
            source_uri: source.to_owned(),
            png: output.into(),
        })
    })()
}
unsafe extern "C" {
    fn webkit_web_view_get_main_resource(view: *mut ffi::WebKitWebView) -> *mut c_void;
}
impl WebSession {
    /// Enable or disable native favicon discovery for this view's whole network profile.
    /// Native loads omit credentials, preserve TLS/destination policy and respect icon CSP.
    /// Opt in before navigation; private cache persistence remains the host's responsibility.
    pub fn set_favicons_enabled(&self, enabled: bool) -> Result<(), FaviconError> {
        let api = api().ok_or(FaviconError::UnsupportedRuntime)?;
        crate::ffi::threading::claim().map_err(|_| FaviconError::WrongThread)?;
        // SAFETY: the live view owns its network session and borrowed data manager.
        unsafe {
            let network = ffi::webkit_web_view_get_network_session(self.web_view);
            let manager =
                crate::ffi::page::sys::webkit_network_session_get_website_data_manager(network);
            if ffi::g_object_get_data(self.web_view.cast(), c"enzui-bounded-favicon-v1".as_ptr())
                .is_null()
            {
                return Err(FaviconError::UnsupportedRuntime);
            }
            (api.enable)(manager.cast(), i32::from(enabled));
        }
        Ok(())
    }
    /// Look up icons already loaded for the current completed document, without page script.
    /// A not-yet-loaded or absent icon returns `NotFound`; retry after native icon loading.
    /// Icons WebKit filed under an earlier same-origin URL of the same document, before
    /// `history.replaceState` or `pushState`, are found too; `document_uri` is the current URL.
    /// At most two lookups retain admission per owner thread, each with a 15-second deadline.
    pub fn favicon(&self) -> Result<FaviconTask, FaviconError> {
        if self.page_hub.host_navigation_pending() {
            return Err(FaviconError::NotReady);
        }
        let api = api().ok_or(FaviconError::UnsupportedRuntime)?;
        crate::ffi::threading::claim().map_err(|_| FaviconError::WrongThread)?;
        // SAFETY: these accessors borrow the session's live native objects.
        let (resource, database) = unsafe {
            if crate::ffi::page::sys::webkit_web_view_is_loading(self.web_view) != 0 {
                return Err(FaviconError::NotReady);
            }
            let network = ffi::webkit_web_view_get_network_session(self.web_view);
            let manager =
                crate::ffi::page::sys::webkit_network_session_get_website_data_manager(network);
            if ffi::g_object_get_data(self.web_view.cast(), c"enzui-bounded-favicon-v1".as_ptr())
                .is_null()
            {
                return Err(FaviconError::UnsupportedRuntime);
            }
            (
                webkit_web_view_get_main_resource(self.web_view),
                (api.database)(manager.cast()),
            )
        };
        if resource.is_null() || database.is_null() {
            return Err(FaviconError::NotReady);
        }
        let document = self
            .current_uri()
            .map_err(|_| FaviconError::NotReady)?
            .ok_or(FaviconError::NotReady)?;
        // Earlier same-origin URLs of this document, tried newest first.
        let origin = crate::local_origins::url_origin(&document);
        let mut fallbacks: Vec<_> = self
            .page_hub
            .document_uris()
            .into_iter()
            .filter(|uri| *uri != document)
            .filter(|uri| origin.is_some() && crate::local_origins::url_origin(uri) == origin)
            .take(4)
            .filter_map(|uri| std::ffi::CString::new(uri).ok())
            .collect();
        // Popped from the end, so the newest earlier URL goes first.
        fallbacks.reverse();
        let document = std::ffi::CString::new(document).map_err(|_| FaviconError::NotReady)?;
        let (task, completion) = LIMITER
            .with(|limiter| NativeTask::start(limiter, Duration::from_secs(15)))
            .map_err(task_error)?;
        // SAFETY: retain both borrowed objects until deferred native completion.
        unsafe {
            ffi::g_object_ref(resource);
            ffi::g_object_ref(self.web_view.cast());
        }
        let request = Box::new(Request {
            completion: Some(completion),
            view: self.web_view,
            resource,
            hub: Rc::downgrade(&self.page_hub),
            load_generation: self.page_hub.load_state().0,
            navigation_intent: self.page_hub.navigation_intent(),
            lifetime: Rc::downgrade(&self.favicon_lifetime),
            identity: self.favicon_identity.clone(),
            view_identity: self.bound_view,
            document: document.to_string_lossy().into_owned(),
            fallbacks,
            _network: self.network_session.clone(),
        });
        // SAFETY: the callback owns this request; native copies the page URI before returning.
        unsafe {
            (api.get)(
                database,
                document.as_ptr(),
                request
                    .completion
                    .as_ref()
                    .expect("favicon request")
                    .cancellable(),
                finished,
                Box::into_raw(request).cast(),
            );
        }
        Ok(FaviconTask(task))
    }
}
