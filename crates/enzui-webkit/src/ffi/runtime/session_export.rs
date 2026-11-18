//! Stock native page exports with bounded host copies and retained callback state.

use std::ffi::{CStr, c_void};
use std::io::Write;
use std::ptr;
use std::rc::{Rc, Weak};

use super::{WebSession, ffi};
use crate::ffi::native_task::{
    NativeTask, NativeTaskCompletion, NativeTaskError, NativeTaskLimiter,
};
use crate::ffi::page::sys::{webkit_uri_response_get_content_length, webkit_web_view_is_loading};
use crate::page_export::{
    OwnedPageExport, PageExportCapabilities, PageExportError, PageExportFormat, PageExportOptions,
};

const CHUNK: usize = 64 * 1024;
const MAX_SNAPSHOT_PIXELS: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_DIMENSION: u32 = 16384;
thread_local! { static LIMITER: NativeTaskLimiter = NativeTaskLimiter::new(2); }

/// Owner-thread asynchronous page export, with bounded retained host output.
///
/// Dispatch the native context and poll this handle. Dropping it requests
/// cancellation. Stock native serialization may finish internally before seeing
/// cancellation; its callback state remains retained until actual completion.
pub struct PageExportTask(NativeTask<Result<OwnedPageExport, PageExportError>>);

impl PageExportTask {
    /// Take one terminal result, if available; this also observes the deadline.
    pub fn take_result(&self) -> Option<Result<OwnedPageExport, PageExportError>> {
        self.0
            .take_result()
            .map(|result| result.map_err(task_error).and_then(|result| result))
    }
    /// Whether completion, cancellation or timeout has made this task terminal.
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
    /// Request cancellation; an internal native serialization already done is not undone.
    pub fn cancel(&self) {
        self.0.cancel();
    }
}

struct Owners {
    view: *mut ffi::WebKitWebView,
    resource: *mut c_void,
    stream: *mut c_void,
    // Retain the Rust guard as well as the native profile while the view exists.
    _network: Option<Rc<crate::ffi::profile::NetworkSession>>,
}
impl Drop for Owners {
    fn drop(&mut self) {
        // SAFETY: these references were retained on the owner thread and are released
        // only after native task teardown through a one-shot deferred source.
        unsafe {
            if !self.stream.is_null() {
                ffi::g_object_unref(self.stream);
            }
            ffi::g_object_unref(self.resource);
            ffi::g_object_unref(self.view.cast());
        }
    }
}

struct Request {
    completion: NativeTaskCompletion<Result<OwnedPageExport, PageExportError>>,
    owners: Owners,
    hub: Weak<crate::ffi::page::PageHub>,
    format: PageExportFormat,
    mime: &'static str,
    limit: usize,
    bytes: Vec<u8>,
}
struct Completed {
    completion: NativeTaskCompletion<Result<OwnedPageExport, PageExportError>>,
    _owners: Owners,
    hub: Weak<crate::ffi::page::PageHub>,
    result: Result<OwnedPageExport, PageExportError>,
}
extern "C" fn complete_later(data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: the one-shot source exclusively owns its completion box.
    let completed = unsafe { Box::from_raw(data.cast::<Completed>()) };
    let Completed {
        completion,
        _owners,
        hub,
        mut result,
    } = *completed;
    if result.is_ok() {
        if hub.upgrade().is_none() {
            result = Err(PageExportError::Cancelled);
        }
        // SAFETY: the deferred completion still retains the view and original resource.
        else if unsafe { webkit_web_view_get_main_resource(_owners.view) } != _owners.resource {
            result = Err(PageExportError::StaleDocument);
        }
    }
    completion.complete(Ok(result));
    drop(_owners);
    ffi::G_FALSE
}
impl Request {
    fn current(&self) -> Result<(), PageExportError> {
        if !self.completion.is_active() || self.hub.upgrade().is_none() {
            return Err(PageExportError::Cancelled);
        }
        // SAFETY: this request retains the native view and original resource identity.
        if unsafe { webkit_web_view_get_main_resource(self.owners.view) } != self.owners.resource {
            return Err(PageExportError::StaleDocument);
        }
        Ok(())
    }

    fn finish(self, result: Result<OwnedPageExport, PageExportError>) {
        let Self {
            completion,
            owners,
            hub,
            ..
        } = self;
        let completed = Box::new(Completed {
            completion,
            _owners: owners,
            hub,
            result,
        });
        // Releasing the last profile/view inside its native GTask callback can
        // invalidate the task's source object during teardown. Admission stays
        // retained until this deferred release as well.
        // SAFETY: the next-dispatch source owns the completion allocation exactly once.
        unsafe { ffi::g_timeout_add(0, complete_later, Box::into_raw(completed).cast()) };
    }
}

impl WebSession {
    /// Public native export capabilities, including allocation-bound limitations.
    pub fn page_export_capabilities(&self) -> PageExportCapabilities {
        let mut capabilities = PageExportCapabilities::WPE;
        if snapshot_budget_available(self.web_view) {
            capabilities.full_document_png = true;
            capabilities.max_snapshot_pixels = Some(MAX_SNAPSHOT_PIXELS);
            capabilities.max_snapshot_dimension = Some(MAX_SNAPSHOT_DIMENSION);
        }
        capabilities
    }

    /// Export the current page without refetching its URL or changing its profile.
    ///
    /// HTML returns original loaded HTML/XHTML bytes, not live DOM serialization.
    /// MHTML uses native serialization and includes loaded subresources; it may be
    /// unavailable in native builds compiled without MHTML. Output is owned, with
    /// at most 16 MiB retained by the host. Native internal resource/archive
    /// allocations occur before public lengths are available and are not bounded
    /// by this API's host limit. Navigation replacing the resource invalidates
    /// the pending result. At most two exports occupy native admission at once.
    ///
    /// Full-document PNG requires a runtime advertising the reviewed native
    /// preallocation cap: 16 megapixels and at most 16,384 pixels per dimension,
    /// including device scale. Stock runtimes are refused before capture because
    /// a JavaScript size preflight can race document changes. PNG encoding uses
    /// one converted row and a bounded output sink, without a full RGBA copy.
    pub fn export_page(
        &self,
        format: PageExportFormat,
        options: &PageExportOptions,
    ) -> Result<PageExportTask, PageExportError> {
        options.validate()?;
        if format == PageExportFormat::FullDocumentPng && !snapshot_budget_available(self.web_view)
        {
            return Err(PageExportError::UnsupportedRuntime(
                "full-document PNG requires a native preallocation-safe capture API",
            ));
        }
        crate::ffi::threading::claim().map_err(|_| PageExportError::WrongThread)?;
        // SAFETY: a live session owns its view and the resource/response borrowed below.
        let (resource, response) = unsafe {
            if webkit_web_view_is_loading(self.web_view) != 0 {
                return Err(PageExportError::NotReady);
            }
            let resource = webkit_web_view_get_main_resource(self.web_view);
            if resource.is_null() {
                return Err(PageExportError::NotReady);
            }
            let response = webkit_web_resource_get_response(resource);
            if response.is_null() {
                return Err(PageExportError::NotReady);
            }
            (resource, response)
        };
        // SAFETY: response is borrowed from the live original main resource.
        let mime = unsafe { ffi::webkit_uri_response_get_mime_type(response) };
        let mime = if mime.is_null() {
            ""
        } else {
            // SAFETY: native getter returns a valid borrowed NUL-terminated MIME string.
            unsafe { CStr::from_ptr(mime) }.to_str().unwrap_or("")
        };
        let mime = if format == PageExportFormat::FullDocumentPng {
            "image/png"
        } else if format == PageExportFormat::Mhtml {
            "multipart/related"
        } else if mime.eq_ignore_ascii_case("text/html") {
            "text/html"
        } else if mime.eq_ignore_ascii_case("application/xhtml+xml") {
            "application/xhtml+xml"
        } else {
            return Err(PageExportError::UnsupportedMime(
                mime.chars().take(128).collect(),
            ));
        };
        // A declared oversized main resource can be rejected before native copying.
        // A smaller/unknown or compressed Content-Length is not an allocation bound.
        if format == PageExportFormat::MainResourceHtml
            // SAFETY: the response remains borrowed from the retained live resource.
            && unsafe { webkit_uri_response_get_content_length(response) } > options.max_bytes as u64
        {
            return Err(PageExportError::OutputTooLarge);
        }
        let (task, completion) = LIMITER
            .with(|limiter| NativeTask::start(limiter, options.timeout))
            .map_err(task_error)?;
        // SAFETY: retain both native objects until after their asynchronous task teardown.
        unsafe {
            ffi::g_object_ref(self.web_view.cast());
            ffi::g_object_ref(resource);
        }
        let request = Box::new(Request {
            completion,
            owners: Owners {
                view: self.web_view,
                resource,
                stream: ptr::null_mut(),
                _network: self.network_session.clone(),
            },
            hub: Rc::downgrade(&self.page_hub),
            format,
            mime,
            limit: options.max_bytes,
            bytes: Vec::new(),
        });
        if let Err(error) = request.current() {
            request.finish(Err(error));
            return Ok(PageExportTask(task));
        }
        // SAFETY: callbacks consume the heap-owned state once and always call native finish.
        unsafe {
            if format == PageExportFormat::FullDocumentPng {
                ffi::webkit_web_view_get_snapshot(
                    self.web_view,
                    1,
                    0,
                    request.completion.cancellable(),
                    snapshot_ready,
                    Box::into_raw(request).cast(),
                );
            } else if format == PageExportFormat::MainResourceHtml {
                webkit_web_resource_get_data(
                    resource,
                    request.completion.cancellable(),
                    html_ready,
                    Box::into_raw(request).cast(),
                );
            } else {
                webkit_web_view_save(
                    self.web_view,
                    0,
                    request.completion.cancellable(),
                    archive_ready,
                    Box::into_raw(request).cast(),
                );
            }
        }
        Ok(PageExportTask(task))
    }
}

fn snapshot_budget_available(view: *mut ffi::WebKitWebView) -> bool {
    // SAFETY: the owner-thread session retains the view; only the reviewed native
    // constructor advertises this exact versioned preallocation-cap value.
    unsafe {
        ffi::g_object_get_data(
            view.cast(),
            c"enzui-full-document-snapshot-max-pixels-v1".as_ptr(),
        ) as usize
            == MAX_SNAPSHOT_PIXELS as usize
    }
}

extern "C" fn snapshot_ready(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: snapshot completion owns the unique request passed to its native call.
    let request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: finish matches this view's native snapshot and transfers the image reference.
    let image =
        unsafe { ffi::webkit_web_view_get_snapshot_finish(source.cast(), result, &mut error) };
    let outcome = if let Some(error) = native_error(error) {
        Err(error)
    } else if let Err(error) = request.current() {
        Err(error)
    } else if image.is_null() {
        Err(PageExportError::Native(
            "native full-document snapshot returned no image".into(),
        ))
    } else {
        encode_snapshot(&request, image)
    };
    if !image.is_null() {
        // SAFETY: finish transferred this one image reference to the callback.
        unsafe {
            ffi::g_object_unref(image.cast());
        }
    }
    request.finish(outcome);
}

struct BoundedSink {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}
impl Write for BoundedSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(std::io::Error::other("PNG exceeds host output cap"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_snapshot(
    request: &Request,
    image: *mut ffi::WebKitImage,
) -> Result<OwnedPageExport, PageExportError> {
    // SAFETY: the callback owns this live image through encoding.
    let (width, height, stride, bytes) = unsafe {
        (
            ffi::webkit_image_get_width(image),
            ffi::webkit_image_get_height(image),
            ffi::webkit_image_get_stride(image),
            ffi::webkit_image_as_bytes(image),
        )
    };
    if width <= 0
        || height <= 0
        || width as u32 > MAX_SNAPSHOT_DIMENSION
        || height as u32 > MAX_SNAPSHOT_DIMENSION
        || (width as u64)
            .checked_mul(height as u64)
            .is_none_or(|pixels| pixels > MAX_SNAPSHOT_PIXELS)
    {
        return Err(PageExportError::OutputTooLarge);
    }
    if bytes.is_null() {
        return Err(PageExportError::Native(
            "native snapshot has no pixel bytes".into(),
        ));
    }
    let mut length = 0;
    // SAFETY: image owns these borrowed GBytes until the callback releases it.
    let pixels = unsafe { ffi::g_bytes_get_data(bytes, &mut length) };
    if pixels.is_null() || length as u64 > MAX_SNAPSHOT_PIXELS * 4 {
        return Err(PageExportError::OutputTooLarge);
    }
    let layout = super::validate_native_snapshot(width, height, stride, length)
        .map_err(|error| PageExportError::Native(error.to_string()))?;
    // SAFETY: native GBytes supplies exactly length initialized bytes, validated above.
    let pixels = unsafe { std::slice::from_raw_parts(pixels.cast::<u8>(), length) };
    let mut sink = BoundedSink {
        bytes: Vec::new(),
        limit: request.limit,
        exceeded: false,
    };
    let encoded: Result<(), PageExportError> = (|| {
        let mut encoder = png::Encoder::new(&mut sink, width as u32, height as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::Fast);
        let mut writer = encoder
            .write_header()
            .map_err(|error| PageExportError::Native(error.to_string()))?;
        {
            let mut stream = writer
                .stream_writer()
                .map_err(|error| PageExportError::Native(error.to_string()))?;
            let mut rgba = vec![0; layout.row_bytes()];
            for row in 0..height as usize {
                request.current()?;
                let start = row * layout.stride();
                for (output, input) in rgba.as_chunks_mut::<4>().0.iter_mut().zip(
                    pixels[start..start + layout.row_bytes()]
                        .as_chunks::<4>()
                        .0
                        .iter(),
                ) {
                    let pixel = if cfg!(target_endian = "little") {
                        [input[2], input[1], input[0], input[3]]
                    } else {
                        [input[1], input[2], input[3], input[0]]
                    };
                    let alpha = u16::from(pixel[3]);
                    // WebKitImage is premultiplied native ARGB; PNG stores straight RGBA.
                    for channel in 0..3 {
                        output[channel] = (u16::from(pixel[channel]) * 255 + alpha / 2)
                            .checked_div(alpha)
                            .unwrap_or(0)
                            .min(255) as u8;
                    }
                    output[3] = pixel[3];
                }
                stream
                    .write_all(&rgba)
                    .map_err(|error| PageExportError::Native(error.to_string()))?;
            }
            stream
                .finish()
                .map_err(|error| PageExportError::Native(error.to_string()))?;
        }
        writer
            .finish()
            .map_err(|error| PageExportError::Native(error.to_string()))?;
        Ok(())
    })();
    if sink.exceeded {
        return Err(PageExportError::OutputTooLarge);
    }
    encoded?;
    Ok(OwnedPageExport::new(
        PageExportFormat::FullDocumentPng,
        "image/png",
        sink.bytes,
    ))
}

extern "C" fn html_ready(source: *mut c_void, result: *mut ffi::GAsyncResult, data: *mut c_void) {
    // SAFETY: get_data receives and transfers the unique callback state to this call.
    let request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    let mut length = 0;
    // SAFETY: source/result belong to the native main-resource get_data operation.
    let bytes =
        unsafe { webkit_web_resource_get_data_finish(source, result, &mut length, &mut error) };
    let outcome = if let Some(error) = native_error(error) {
        Err(error)
    } else if let Err(error) = request.current() {
        Err(error)
    } else if length > request.limit {
        Err(PageExportError::OutputTooLarge)
    } else if bytes.is_null() || length == 0 {
        Err(PageExportError::Native(
            "native main resource returned no HTML".into(),
        ))
    } else {
        // SAFETY: finish transferred exactly length bytes; host copy occurs only after cap check.
        let owned = unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec();
        Ok(OwnedPageExport::new(request.format, request.mime, owned))
    };
    // SAFETY: native finish transferred this allocation, including on error paths.
    unsafe {
        ffi::g_free(bytes.cast());
    }
    request.finish(outcome);
}

extern "C" fn archive_ready(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: save transfers this callback's unique heap request.
    let mut request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: finish matches save on this view/result; returned stream is transfer-full.
    request.owners.stream =
        unsafe { webkit_web_view_save_finish(source.cast(), result, &mut error) };
    if let Some(error) = native_error(error) {
        request.finish(Err(error));
    } else if let Err(error) = request.current() {
        request.finish(Err(error));
    } else if request.owners.stream.is_null() {
        request.finish(Err(PageExportError::Native(
            "native MHTML returned no stream".into(),
        )));
    } else {
        read_next(request);
    }
}

fn read_next(request: Box<Request>) {
    if let Err(error) = request.current() {
        request.finish(Err(error));
        return;
    }
    // One byte beyond the remaining budget detects overflow without retaining it.
    let count = CHUNK.min(request.limit - request.bytes.len() + 1);
    // SAFETY: the request owns stream and cancellable; callback uniquely consumes the box.
    unsafe {
        g_input_stream_read_bytes_async(
            request.owners.stream,
            count,
            0,
            request.completion.cancellable(),
            archive_chunk,
            Box::into_raw(request).cast(),
        );
    }
}

extern "C" fn archive_chunk(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: each read callback exclusively consumes the request passed to that read.
    let mut request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: native finish matches this stream/result and transfers one GBytes reference.
    let bytes = unsafe { g_input_stream_read_bytes_finish(source, result, &mut error) };
    let mut length = 0;
    // SAFETY: non-null result bytes remain owned until their unref below.
    let buffer = if bytes.is_null() {
        ptr::null()
    } else {
        unsafe { ffi::g_bytes_get_data(bytes, &mut length) }
    };
    let outcome = if let Some(error) = native_error(error) {
        Err(error)
    } else if let Err(error) = request.current() {
        Err(error)
    } else if bytes.is_null() {
        Err(PageExportError::Native(
            "MHTML stream returned no bytes".into(),
        ))
    } else if length > request.limit - request.bytes.len() {
        Err(PageExportError::OutputTooLarge)
    } else if length > 0 && buffer.is_null() {
        Err(PageExportError::Native(
            "MHTML stream returned an invalid buffer".into(),
        ))
    } else {
        Ok(())
    };
    if outcome.is_ok() && length > 0 {
        // SAFETY: native GBytes provides length bytes; the cap was checked before extending.
        request
            .bytes
            .extend_from_slice(unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) });
    }
    if !bytes.is_null() {
        // SAFETY: finish transferred exactly this reference to the callback.
        unsafe {
            ffi::g_bytes_unref(bytes);
        }
    }
    if let Err(error) = outcome {
        request.finish(Err(error));
    } else if length == 0 {
        if request.bytes.is_empty() {
            request.finish(Err(PageExportError::Native(
                "native MHTML archive is empty".into(),
            )));
        } else {
            let artifact = OwnedPageExport::new(
                request.format,
                request.mime,
                std::mem::take(&mut request.bytes),
            );
            request.finish(Ok(artifact));
        }
    } else {
        read_next(request);
    }
}

fn task_error(error: NativeTaskError) -> PageExportError {
    match error {
        NativeTaskError::WrongThread => PageExportError::WrongThread,
        NativeTaskError::Busy => PageExportError::Busy,
        NativeTaskError::Cancelled => PageExportError::Cancelled,
        NativeTaskError::TimedOut => PageExportError::TimedOut,
        NativeTaskError::InvalidInput(message) => PageExportError::InvalidInput(message),
        NativeTaskError::Native(message) => PageExportError::Native(message),
    }
}
fn native_error(error: *mut ffi::GError) -> Option<PageExportError> {
    if error.is_null() {
        return None;
    }
    // SAFETY: native finish transferred a live GError with these fixed fields.
    let unsupported = unsafe { (*error).domain == g_io_error_quark() && (*error).code == 15 };
    // SAFETY: take_gerror consumes the owned native allocation exactly once.
    let mapped = task_error(unsafe { crate::ffi::native_task::take_gerror(error) });
    Some(if unsupported {
        PageExportError::UnsupportedRuntime("native runtime does not support this export")
    } else {
        mapped
    })
}

type Callback = extern "C" fn(*mut c_void, *mut ffi::GAsyncResult, *mut c_void);
unsafe extern "C" {
    fn webkit_web_view_get_main_resource(view: *mut ffi::WebKitWebView) -> *mut c_void;
    fn webkit_web_resource_get_response(resource: *mut c_void) -> *mut ffi::WebKitURIResponse;
    fn webkit_web_resource_get_data(
        resource: *mut c_void,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_web_resource_get_data_finish(
        resource: *mut c_void,
        result: *mut ffi::GAsyncResult,
        length: *mut usize,
        error: *mut *mut ffi::GError,
    ) -> *mut u8;
    fn webkit_web_view_save(
        view: *mut ffi::WebKitWebView,
        mode: i32,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_web_view_save_finish(
        view: *mut ffi::WebKitWebView,
        result: *mut ffi::GAsyncResult,
        error: *mut *mut ffi::GError,
    ) -> *mut c_void;
    fn g_input_stream_read_bytes_async(
        stream: *mut c_void,
        count: usize,
        priority: i32,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn g_input_stream_read_bytes_finish(
        stream: *mut c_void,
        result: *mut ffi::GAsyncResult,
        error: *mut *mut ffi::GError,
    ) -> *mut ffi::GBytes;
    fn g_io_error_quark() -> u32;
}
