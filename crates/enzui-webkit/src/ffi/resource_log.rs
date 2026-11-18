//! Opt-in native resource signals. No page script or performance-entry synthesis.
//!
//! Paths remain visible; query, fragment, userinfo, capture URLs, error text and
//! all non-allowlisted headers are excluded. Do not persist a log without consent.

use super::WebSession;
use crate::ffi::{page::PageHub, wpe};
use crate::resource::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::{c_char, c_void};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const CAPACITY: usize = 512;
const MAX_RESOURCES: usize = 128;
#[repr(C)]
struct NativeWeak {
    pointer: *mut c_void,
}
unsafe extern "C" {
    fn g_weak_ref_init(reference: *mut NativeWeak, object: *mut c_void);
    fn g_weak_ref_get(reference: *mut NativeWeak) -> *mut c_void;
    fn g_weak_ref_clear(reference: *mut NativeWeak);
    fn webkit_uri_request_get_uri(request: *mut wpe::WebKitURIRequest) -> *const c_char;
    fn webkit_uri_request_get_http_method(request: *mut wpe::WebKitURIRequest) -> *const c_char;
    fn webkit_uri_request_get_http_headers(
        request: *mut wpe::WebKitURIRequest,
    ) -> *mut wpe::SoupMessageHeaders;
    fn webkit_web_resource_get_response(resource: *mut c_void) -> *mut wpe::WebKitURIResponse;
    fn webkit_uri_response_get_status_code(response: *mut wpe::WebKitURIResponse) -> u32;
    fn webkit_uri_response_get_mime_type(response: *mut wpe::WebKitURIResponse) -> *const c_char;
    fn webkit_uri_response_get_http_headers(
        response: *mut wpe::WebKitURIResponse,
    ) -> *mut wpe::SoupMessageHeaders;
    fn webkit_uri_response_get_content_length(response: *mut wpe::WebKitURIResponse) -> u64;
}

struct ViewBinding {
    weak: Box<NativeWeak>,
    handler: u64,
}
impl ViewBinding {
    fn disconnect(&mut self) {
        if self.handler == 0 {
            return;
        }
        // SAFETY: the initialized stable weak ref returns an owned live object or NULL.
        let object = unsafe { g_weak_ref_get(&mut *self.weak) };
        if !object.is_null() {
            // SAFETY: this owned reference keeps the view alive while its handler is detached.
            unsafe {
                wpe::g_signal_handler_disconnect(object, self.handler);
                wpe::g_object_unref(object);
            }
        }
        self.handler = 0;
    }
}
impl Drop for ViewBinding {
    fn drop(&mut self) {
        self.disconnect();
        // SAFETY: one clear balances this stable weak ref's initialization.
        unsafe { g_weak_ref_clear(&mut *self.weak) };
    }
}
struct Binding {
    object: *mut c_void,
    handlers: Vec<u64>,
}
impl Drop for Binding {
    fn drop(&mut self) {
        for id in self.handlers.drain(..) {
            // SAFETY: this binding retains the object and owns every listed handler.
            unsafe { wpe::g_signal_handler_disconnect(self.object, id) };
        }
        // SAFETY: the binding owns one reference obtained at creation.
        unsafe { wpe::g_object_unref(self.object) };
    }
}
struct Track {
    state: Weak<State>,
    id: u64,
    navigation: u64,
    start: Instant,
    failed: Cell<bool>,
    done: Cell<bool>,
}
struct ResourceBinding {
    _binding: Binding,
    track: Rc<Track>,
}
struct State {
    hub: Weak<PageHub>,
    log_id: u64,
    view: Option<crate::web::ViewId>,
    next: Cell<u64>,
    dropped: Cell<u64>,
    events: RefCell<VecDeque<ResourceEvent>>,
    resources: RefCell<Vec<ResourceBinding>>,
}
impl State {
    fn emit(&self, track: &Track, kind: ResourceEventKind) {
        if self.hub.upgrade().is_none() {
            return;
        }
        let mut queue = self.events.borrow_mut();
        if queue.len() == CAPACITY {
            queue.pop_front();
            self.drop_one();
        }
        queue.push_back(ResourceEvent {
            log_id: self.log_id,
            view: self.view,
            navigation: track.navigation,
            resource_id: track.id,
            elapsed: track.start.elapsed(),
            network_timing: ResourceField::Unavailable(ResourceUnavailable::Unsupported),
            kind,
        });
    }
    fn drop_one(&self) {
        self.dropped.set(self.dropped.get().saturating_add(1));
    }
}

/// A bounded, owner-thread native resource log, independent of the page-event queue.
///
/// Open before loading the target page. Drain events regularly: at most 128 native
/// resources are tracked and 512 events retained; omitted items increment dropped().
/// Closing the log disconnects all signals. A log can outlive its logical view,
/// but then is_active() is false and no new events are accepted. Reopen after
/// recovery. Router identity is captured at opening; bind the session first.
/// This does not enable developer extras or start an inspector listener.
pub struct ResourceLog {
    binding: ViewBinding,
    state: Rc<State>,
}
impl ResourceLog {
    /// Whether this log still belongs to a live logical session.
    pub fn is_active(&self) -> bool {
        self.state.hub.upgrade().is_some()
    }
    /// Subscription identity used in every event.
    pub fn id(&self) -> u64 {
        self.state.log_id
    }
    /// Count evicted events and resources omitted at the tracking limit.
    pub fn dropped(&self) -> u64 {
        self.state.dropped.get()
    }
    /// Whether bounded native events are waiting for the owner to drain them.
    pub fn has_events(&self) -> bool {
        !self.state.events.borrow().is_empty()
    }
    /// Drain bounded owned events and release completed native resource handlers.
    pub fn take_events(&self) -> Vec<ResourceEvent> {
        self.state
            .resources
            .borrow_mut()
            .retain(|r| !r.track.done.get());
        self.state.events.borrow_mut().drain(..).collect()
    }
}
impl Drop for ResourceLog {
    fn drop(&mut self) {
        self.binding.disconnect();
        self.state.resources.borrow_mut().clear();
    }
}
impl WebSession {
    /// Subscribe to native resource diagnostics without enabling developer extras.
    ///
    /// # Errors
    /// Returns a native error if the required resource-start signal is unavailable.
    pub fn open_resource_log(
        &self,
    ) -> Result<ResourceLog, crate::ffi::native_task::NativeTaskError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let state = Rc::new(State {
            hub: Rc::downgrade(&self.page_hub),
            log_id: NEXT.fetch_add(1, Ordering::Relaxed),
            view: self.bound_view,
            next: Cell::new(1),
            dropped: Cell::new(0),
            events: RefCell::default(),
            resources: RefCell::default(),
        });
        let object = self.web_view.cast();
        let mut weak = Box::new(NativeWeak {
            pointer: std::ptr::null_mut(),
        });
        // SAFETY: the session retains the live view during initialization of this stable weak ref.
        unsafe { g_weak_ref_init(&mut *weak, object) };
        let mut binding = ViewBinding { weak, handler: 0 };
        // SAFETY: callback signature exactly matches WebView::resource-load-started.
        let callback = unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void),
                extern "C" fn(),
            >(started)
        };
        let id = connect(
            object,
            c"resource-load-started",
            callback,
            Rc::downgrade(&state),
        );
        if id == 0 {
            return Err(crate::ffi::native_task::NativeTaskError::Native(
                "native resource-start signal unavailable".into(),
            ));
        }
        binding.handler = id;
        Ok(ResourceLog { binding, state })
    }
}

fn connect<T>(
    object: *mut c_void,
    name: &std::ffi::CStr,
    callback: extern "C" fn(),
    data: T,
) -> u64 {
    extern "C" fn destroy<T>(data: *mut c_void, _closure: *mut c_void) {
        // SAFETY: each connection owns exactly one allocation of its declared userdata.
        drop(unsafe { Box::from_raw(data.cast::<T>()) });
    }
    let data = Box::into_raw(Box::new(data));
    // SAFETY: caller provides the matching signal ABI; the destroy notify owns heap userdata.
    let id = unsafe {
        wpe::g_signal_connect_data(
            object,
            name.as_ptr(),
            callback,
            data.cast(),
            destroy::<T> as *const () as *mut c_void,
            0,
        )
    };
    if id == 0 {
        // SAFETY: unsuccessful connection does not take ownership of userdata.
        drop(unsafe { Box::from_raw(data) });
    }
    id
}
extern "C" fn started(
    _view: *mut c_void,
    resource: *mut c_void,
    request: *mut c_void,
    data: *mut c_void,
) {
    // SAFETY: connection holds this typed weak state until disconnect.
    let Some(state) = (unsafe { &*data.cast::<Weak<State>>() }).upgrade() else {
        return;
    };
    let Some(hub) = state.hub.upgrade() else {
        return;
    };
    let mut resources = state.resources.borrow_mut();
    resources.retain(|r| !r.track.done.get());
    if resources.len() >= MAX_RESOURCES {
        state.drop_one();
        return;
    }
    let id = state.next.get();
    state.next.set(id.saturating_add(1));
    let track = Rc::new(Track {
        state: Rc::downgrade(&state),
        id,
        navigation: hub.load_state().0,
        start: Instant::now(),
        failed: Cell::new(false),
        done: Cell::new(false),
    });
    // SAFETY: resource-load-started supplies a live resource; binding takes a reference.
    unsafe { wpe::g_object_ref(resource) };
    let mut binding = Binding {
        object: resource,
        handlers: Vec::new(),
    };
    macro_rules! handler {
        ($name:expr, $f:ident, $ty:ty) => {{
            // SAFETY: the specified native signal and typed callback have matching ABI.
            let callback = unsafe { std::mem::transmute::<$ty, extern "C" fn()>($f) };
            let id = connect(resource, $name, callback, track.clone());
            if id != 0 {
                binding.handlers.push(id);
            } else {
                state.drop_one();
            }
        }};
    }
    handler!(
        c"sent-request",
        sent,
        extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void)
    );
    handler!(
        c"notify::response",
        response,
        extern "C" fn(*mut c_void, *mut c_void, *mut c_void)
    );
    handler!(
        c"failed",
        failed,
        extern "C" fn(*mut c_void, *mut wpe::GError, *mut c_void)
    );
    handler!(
        c"failed-with-tls-errors",
        tls_failed,
        extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void)
    );
    handler!(
        c"finished",
        finished,
        extern "C" fn(*mut c_void, *mut c_void)
    );
    state.emit(
        &track,
        ResourceEventKind::Started(read_request(request, &hub)),
    );
    resources.push(ResourceBinding {
        _binding: binding,
        track,
    });
}
fn track(data: *mut c_void) -> Rc<Track> {
    // SAFETY: resource connection owns one Rc<Track> of this exact type.
    unsafe { &*data.cast::<Rc<Track>>() }.clone()
}
extern "C" fn sent(
    _resource: *mut c_void,
    request: *mut c_void,
    redirect: *mut c_void,
    data: *mut c_void,
) {
    let track = track(data);
    let Some(state) = track.state.upgrade() else {
        return;
    };
    let Some(hub) = state.hub.upgrade() else {
        return;
    };
    // SAFETY: a non-null redirect response is borrowed during this signal.
    let redirect_status = (!redirect.is_null())
        .then(|| unsafe { webkit_uri_response_get_status_code(redirect.cast()) });
    state.emit(
        &track,
        ResourceEventKind::Sent {
            request: read_request(request, &hub),
            redirect_status,
        },
    );
}
extern "C" fn response(resource: *mut c_void, _param: *mut c_void, data: *mut c_void) {
    let track = track(data);
    let Some(state) = track.state.upgrade() else {
        return;
    };
    // SAFETY: signal source remains a live native resource during its callback.
    let response = unsafe { webkit_web_resource_get_response(resource) };
    if response.is_null() {
        return;
    }
    // SAFETY: these getters return borrowed metadata of the live response.
    let (status, mime, headers, length) = unsafe {
        (
            webkit_uri_response_get_status_code(response),
            webkit_uri_response_get_mime_type(response),
            webkit_uri_response_get_http_headers(response),
            webkit_uri_response_get_content_length(response),
        )
    };
    state.emit(
        &track,
        ResourceEventKind::Response(ResourceResponse {
            status: if status == 0 {
                missing()
            } else {
                ResourceField::Available(status)
            },
            mime_type: field(mime, 256),
            headers: read_headers(headers.cast(), false),
            content_length: if length == 0 {
                missing()
            } else {
                ResourceField::Available(length)
            },
        }),
    );
}
extern "C" fn failed(_resource: *mut c_void, error: *mut wpe::GError, data: *mut c_void) {
    let track = track(data);
    track.failed.set(true);
    let Some(state) = track.state.upgrade() else {
        return;
    };
    if error.is_null() {
        return;
    }
    // SAFETY: native failed signal borrows a valid GError during this callback.
    let (domain, code) = unsafe { ((*error).domain, (*error).code) };
    state.emit(&track, ResourceEventKind::Failed { domain, code });
}
extern "C" fn tls_failed(
    _resource: *mut c_void,
    _certificate: *mut c_void,
    flags: u32,
    data: *mut c_void,
) {
    let track = track(data);
    track.failed.set(true);
    if let Some(state) = track.state.upgrade() {
        state.emit(&track, ResourceEventKind::TlsFailed { flags });
    }
}
extern "C" fn finished(_resource: *mut c_void, data: *mut c_void) {
    let track = track(data);
    track.done.set(true);
    if let Some(state) = track.state.upgrade() {
        state.emit(
            &track,
            ResourceEventKind::Finished {
                failed: track.failed.get(),
            },
        );
    }
}
fn missing<T>() -> ResourceField<T> {
    ResourceField::Unavailable(ResourceUnavailable::NotReported)
}
fn read_text(pointer: *const c_char, maximum: usize) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    for i in 0..=maximum {
        // SAFETY: native string getters return NUL-terminated strings; stop at NUL or the cap.
        let byte = unsafe { pointer.add(i).read() as u8 };
        if byte == 0 {
            return String::from_utf8(bytes).ok();
        }
        if i == maximum {
            return None;
        }
        bytes.push(byte);
    }
    None
}
fn field(pointer: *const c_char, maximum: usize) -> ResourceField<String> {
    match read_text(pointer, maximum) {
        Some(value) => {
            ResourceField::Available(value.chars().filter(|c| !c.is_control()).collect())
        }
        None if pointer.is_null() => missing(),
        None => ResourceField::Unavailable(ResourceUnavailable::Redacted),
    }
}
fn read_request(request: *mut c_void, hub: &PageHub) -> ResourceRequest {
    if request.is_null() {
        return ResourceRequest {
            url: missing(),
            method: missing(),
            headers: missing(),
        };
    }
    // SAFETY: the native signal provides a live request throughout these getters.
    let (uri, method, headers) = unsafe {
        (
            webkit_uri_request_get_uri(request.cast()),
            webkit_uri_request_get_http_method(request.cast()),
            webkit_uri_request_get_http_headers(request.cast()),
        )
    };
    let url = match read_text(uri, 4096) {
        Some(url)
            if (url.starts_with("http://") || url.starts_with("https://"))
                && !hub.is_captured_url(&url) =>
        {
            ResourceField::Available(
                crate::web::policy::PolicyUrl::new(url)
                    .redacted()
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect(),
            )
        }
        _ => ResourceField::Unavailable(ResourceUnavailable::Redacted),
    };
    ResourceRequest {
        url,
        method: field(method, 32),
        headers: read_headers(headers.cast(), true),
    }
}
fn read_headers(headers: *mut c_void, request: bool) -> ResourceField<Vec<ResourceHeader>> {
    if headers.is_null() {
        return missing();
    }
    let names: &[(&'static str, &std::ffi::CStr)] = if request {
        &[
            ("accept", c"accept"),
            ("content-type", c"content-type"),
            ("range", c"range"),
        ]
    } else {
        &[
            ("content-type", c"content-type"),
            ("content-length", c"content-length"),
            ("content-encoding", c"content-encoding"),
            ("cache-control", c"cache-control"),
            ("accept-ranges", c"accept-ranges"),
        ]
    };
    ResourceField::Available(
        names
            .iter()
            .filter_map(|&(name, native)| {
                // SAFETY: headers is a borrowed SoupMessageHeaders and each header name is NUL-terminated.
                let value =
                    unsafe { wpe::soup_message_headers_get_one(headers.cast(), native.as_ptr()) };
                read_text(value, 512).map(|value| ResourceHeader {
                    name,
                    value: value.chars().filter(|c| !c.is_control()).collect(),
                })
            })
            .collect(),
    )
}
