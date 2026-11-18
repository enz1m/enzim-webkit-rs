use super::*;
use crate::ffi::native_task::{
    NativeTask, NativeTaskCompletion, NativeTaskError, NativeTaskLimiter,
};
use crate::ffi::page::sys::JSCValue;
use std::sync::OnceLock;

type Begin = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    *mut c_void,
    extern "C" fn(*mut c_void, *mut ffi::GAsyncResult, *mut c_void),
    *mut c_void,
);
type Finish = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    *mut ffi::GAsyncResult,
    *mut *mut ffi::GError,
) -> *mut JSCValue;

struct Api {
    begin: Begin,
    finish: Finish,
}
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
unsafe extern "C" {
    fn jsc_value_is_string(value: *mut JSCValue) -> ffi::GBoolean;
    fn jsc_value_to_string_as_bytes(value: *mut JSCValue) -> *mut ffi::GBytes;
}
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: both names belong to the reviewed runtime's fixed copy-capture ABI.
        let (begin, finish) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_copy_selection".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_copy_selection_finish".as_ptr(),
                ),
            )
        };
        if begin.is_null() || finish.is_null() {
            return None;
        }
        // SAFETY: these signatures match the two reviewed exported declarations.
        Some(unsafe {
            Api {
                begin: std::mem::transmute::<*mut c_void, Begin>(begin),
                finish: std::mem::transmute::<*mut c_void, Finish>(finish),
            }
        })
    })
    .as_ref()
}

thread_local! { static LIMITER: NativeTaskLimiter = NativeTaskLimiter::new(2); }
type ResultTask = NativeTask<Result<PageSelection, ClipboardRouteError>>;
type Completion = NativeTaskCompletion<Result<PageSelection, ClipboardRouteError>>;

struct Owners {
    view: *mut ffi::WebKitWebView,
    _network: Option<Rc<crate::ffi::profile::NetworkSession>>,
}
impl Drop for Owners {
    fn drop(&mut self) {
        // SAFETY: this owner-thread reference is released after native GTask teardown.
        unsafe { ffi::g_object_unref(self.view.cast()) };
    }
}
struct Request {
    completion: Completion,
    owners: Owners,
    finish: Finish,
}
struct Completed {
    completion: Completion,
    _owners: Owners,
    result: Result<PageSelection, ClipboardRouteError>,
}

extern "C" fn complete_later(data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: the one-shot source owns the box transferred by the ready callback.
    let completed = unsafe { Box::from_raw(data.cast::<Completed>()) };
    let Completed {
        completion,
        _owners,
        result,
    } = *completed;
    completion.complete(Ok(result));
    drop(_owners);
    ffi::G_FALSE
}

pub(super) fn begin(session: &WebSession) -> Result<ResultTask, ClipboardRouteError> {
    let api = api().ok_or(ClipboardRouteError::UnsupportedRuntime)?;
    let (task, completion) = LIMITER
        .with(|limit| {
            NativeTask::start(
                limit,
                std::time::Duration::from_millis(u64::from(COPY_DEADLINE_MS)),
            )
        })
        .map_err(task_error)?;
    // SAFETY: the session borrows a live view on its native owner thread.
    unsafe { ffi::g_object_ref(session.web_view.cast()) };
    let request = Box::new(Request {
        completion,
        owners: Owners {
            view: session.web_view,
            _network: session.network_session.clone(),
        },
        finish: api.finish,
    });
    // SAFETY: the request retains the view, network guard and cancellable through callback teardown.
    unsafe {
        (api.begin)(
            session.web_view,
            request.completion.cancellable(),
            ready,
            Box::into_raw(request).cast(),
        )
    };
    Ok(task)
}

extern "C" fn ready(source: *mut c_void, result: *mut ffi::GAsyncResult, data: *mut c_void) {
    // SAFETY: native invokes this callback once with its unique request box.
    let request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: finish matches the exact native begin operation and transfers its result/error.
    let value = unsafe { (request.finish)(source.cast(), result, &mut error) };
    let result = if !error.is_null() {
        // SAFETY: finish transferred ownership of this native error.
        Err(task_error(unsafe {
            crate::ffi::native_task::take_gerror(error)
        }))
    } else if !request.completion.is_active() {
        Err(ClipboardRouteError::PageDidNotCopy)
    } else {
        read_text(value)
    };
    if !value.is_null() {
        // SAFETY: finish transferred one owned JSCValue reference even on a native error.
        unsafe { ffi::g_object_unref(value.cast()) };
    }
    let Request {
        completion, owners, ..
    } = *request;
    let completed = Box::new(Completed {
        completion,
        _owners: owners,
        result,
    });
    // Releasing the last native view in its GTask callback can invalidate GTask's later teardown.
    // SAFETY: the one-shot source owns completion and retained owners until the next dispatch.
    unsafe { ffi::g_timeout_add(0, complete_later, Box::into_raw(completed).cast()) };
}

fn read_text(value: *mut JSCValue) -> Result<PageSelection, ClipboardRouteError> {
    // SAFETY: value is NULL or the live transfer-full result of the native copy command.
    if value.is_null() || unsafe { jsc_value_is_string(value) } == ffi::G_FALSE {
        return Err(ClipboardRouteError::PageDidNotCopy);
    }
    // SAFETY: a live JSC string transfers its UTF-8 byte representation without C-string truncation.
    let bytes = unsafe { jsc_value_to_string_as_bytes(value) };
    if bytes.is_null() {
        return Err(ClipboardRouteError::PageDidNotCopy);
    }
    let limit = crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES;
    let mut size = 0;
    // SAFETY: this owned GBytes remains live until the bounded copy completes.
    let pointer = unsafe { ffi::g_bytes_get_data(bytes, &mut size) };
    let result = if size > limit {
        Err(ClipboardRouteError::TextTooLarge { size, limit })
    } else if pointer.is_null() || size == 0 {
        Err(ClipboardRouteError::PageDidNotCopy)
    } else {
        // SAFETY: GBytes reports exactly size readable bytes while its reference is retained.
        let data = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size) };
        std::str::from_utf8(data)
            .map(|text| PageSelection {
                text: text.to_owned(),
            })
            .map_err(|_| ClipboardRouteError::Native("native copy text is not UTF-8".into()))
    };
    // SAFETY: release the sole transferred byte-container reference on every path.
    unsafe { ffi::g_bytes_unref(bytes) };
    result
}

pub(super) fn task_error(error: NativeTaskError) -> ClipboardRouteError {
    match error {
        NativeTaskError::Cancelled | NativeTaskError::TimedOut => {
            ClipboardRouteError::PageDidNotCopy
        }
        NativeTaskError::Native(message) if message.contains("ENZUI_COPY_TEXT_TOO_LARGE") => {
            let limit = crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES;
            ClipboardRouteError::TextTooLarge {
                size: limit + 1,
                limit,
            }
        }
        NativeTaskError::Native(message)
            if message.contains("ENZUI_COPY_NO_TEXT")
                || message.contains("ENZUI_COPY_INVALID_TARGET") =>
        {
            ClipboardRouteError::PageDidNotCopy
        }
        other => ClipboardRouteError::Native(other.to_string()),
    }
}
