//! Native, cancellable PDF export without host filesystem access.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::page::PageEvent;
use crate::printing::{PdfPrintError, PdfPrintId, PdfPrintSettings};

const MAX_PDF_BYTES: usize = 64 * 1024 * 1024;
static NEXT_EXPORT: AtomicU64 = AtomicU64::new(1);

type Export = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    u64,
    f64,
    f64,
    f64,
    f64,
    f64,
    f64,
    f64,
    u32,
    u32,
    ffi::GBoolean,
    *mut c_void,
    extern "C" fn(*mut c_void, *mut ffi::GAsyncResult, *mut c_void),
    *mut c_void,
);
type Finish = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    *mut ffi::GAsyncResult,
    *mut *mut ffi::GError,
) -> *mut ffi::GBytes;

struct NativeApi {
    export: Export,
    finish: Finish,
}

#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

unsafe extern "C" {
    fn g_io_error_quark() -> u32;
}

fn native_api() -> Option<&'static NativeApi> {
    static API: OnceLock<Option<NativeApi>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: RTLD_DEFAULT searches already loaded objects; names are NUL-terminated.
        let (export, finish) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_export_pdf".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_view_enzui_export_pdf_finish".as_ptr(),
                ),
            )
        };
        if export.is_null() || finish.is_null() {
            return None;
        }
        // SAFETY: these two private symbols have the reviewed WPE fork's fixed C ABI.
        Some(unsafe {
            NativeApi {
                export: std::mem::transmute::<*mut c_void, Export>(export),
                finish: std::mem::transmute::<*mut c_void, Finish>(finish),
            }
        })
    })
    .as_ref()
}

#[derive(Clone, Default)]
pub(super) struct PdfExportRegistry {
    pending: Rc<RefCell<BTreeMap<PdfPrintId, *mut c_void>>>,
}

impl PdfExportRegistry {
    pub(super) fn cancel_all(&self) {
        let retained: Vec<_> = self
            .pending
            .borrow()
            .values()
            .map(|&value| {
                // SAFETY: registry entries own live GCancellable references.
                unsafe { ffi::g_object_ref(value) }
            })
            .collect();
        for cancellable in retained {
            // SAFETY: a temporary reference keeps cancellation alive across callbacks.
            unsafe {
                ffi::g_cancellable_cancel(cancellable);
                ffi::g_object_unref(cancellable);
            }
        }
    }

    fn cancel(&self, id: PdfPrintId) -> bool {
        let cancellable = self.pending.borrow().get(&id).map(|&value| {
            // SAFETY: registry entries own live GCancellable references.
            unsafe { ffi::g_object_ref(value) }
        });
        let Some(cancellable) = cancellable else {
            return false;
        };
        // SAFETY: the temporary reference lives through cancellation and release.
        unsafe {
            ffi::g_cancellable_cancel(cancellable);
            ffi::g_object_unref(cancellable);
        }
        true
    }
}

struct Completion {
    registry: PdfExportRegistry,
    hub: std::rc::Weak<crate::ffi::page::PageHub>,
    id: PdfPrintId,
    finish: Finish,
}

extern "C" fn finished(view: *mut c_void, result: *mut ffi::GAsyncResult, data: *mut c_void) {
    // SAFETY: exactly one completion consumes the box passed to the native async call.
    let request = unsafe { Box::from_raw(data.cast::<Completion>()) };
    let hub = request.hub.upgrade();
    let mut error = ptr::null_mut();
    // SAFETY: this callback carries the native view and result for this export operation.
    let bytes = unsafe { (request.finish)(view.cast(), result, &mut error) };
    let outcome = if !error.is_null() {
        // SAFETY: finish returned an owned GError and its NUL-terminated message.
        let outcome = unsafe {
            if (*error).domain == g_io_error_quark() && (*error).code == 19 {
                PdfPrintError::Cancelled
            } else if (*error).domain == g_io_error_quark() && (*error).code == 12 {
                PdfPrintError::OutputTooLarge
            } else {
                let message = if (*error).message.is_null() {
                    "native PDF export failed".to_owned()
                } else {
                    crate::native_diagnostic::read_bounded_diagnostic((*error).message, 2048)
                };
                PdfPrintError::Failed(message)
            }
        };
        // SAFETY: this branch owns the native error.
        unsafe { ffi::g_error_free(error) };
        Err(outcome)
    } else if bytes.is_null() {
        Err(PdfPrintError::Failed(
            "native export returned no PDF".into(),
        ))
    } else {
        let mut length = 0;
        // SAFETY: the returned GBytes remains owned until after the bounded copy.
        let buffer = unsafe { ffi::g_bytes_get_data(bytes, &mut length) };
        if hub.is_none() {
            Err(PdfPrintError::Cancelled)
        } else if length > MAX_PDF_BYTES {
            Err(PdfPrintError::OutputTooLarge)
        } else if buffer.is_null() || length < 5 {
            Err(PdfPrintError::Failed(
                "native export returned an empty PDF".into(),
            ))
        } else {
            // SAFETY: GBytes provides exactly `length` initialized bytes, bounded above.
            let pdf = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
            if pdf.starts_with(b"%PDF-") {
                Ok(crate::printing::PdfDocument::new(pdf.to_vec()))
            } else {
                Err(PdfPrintError::Failed(
                    "native export returned invalid PDF data".into(),
                ))
            }
        }
    };
    if !bytes.is_null() {
        // SAFETY: finish transferred one GBytes reference to this callback.
        unsafe { ffi::g_bytes_unref(bytes) };
    }
    let cancellable = request.registry.pending.borrow_mut().remove(&request.id);
    if let Some(cancellable) = cancellable {
        // SAFETY: removal transfers the registry's one reference to this callback.
        unsafe { ffi::g_object_unref(cancellable) };
    }
    if let Some(hub) = hub {
        hub.push(PageEvent::PdfExportFinished {
            id: request.id,
            result: outcome,
        });
    }
}

impl WebSession {
    /// Whether the loaded native runtime exposes paginated PDF export.
    pub fn supports_pdf_export(&self) -> bool {
        native_api().is_some()
    }

    /// Export the main document as a paginated PDF without writing a file.
    ///
    /// Completion arrives through [`PageEvent::PdfExportFinished`]. Only one export
    /// may be active per session. Drain the prior PDF completion before starting
    /// another export, so queued PDF data cannot accumulate. Navigation and
    /// session teardown cancel active exports. CSS
    /// print styles apply; documents are limited to 256 paginated pages, with
    /// at most 64 MiB of PDF output.
    /// The host chooses any destination or print portal after successful completion.
    ///
    /// # Errors
    /// Returns a typed refusal for invalid settings, a busy/unavailable session or
    /// a native runtime without the reviewed toolkit-free export API.
    pub fn export_pdf(&self, settings: &PdfPrintSettings) -> Result<PdfPrintId, PdfPrintError> {
        settings.validate()?;
        self.require_navigable()
            .map_err(|_| PdfPrintError::SessionUnavailable)?;
        if !self.pdf_exports.pending.borrow().is_empty() || self.page_hub.has_pdf_export_result() {
            return Err(PdfPrintError::Busy);
        }
        let api = native_api().ok_or(PdfPrintError::UnsupportedRuntime)?;
        let id = PdfPrintId(
            NEXT_EXPORT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| PdfPrintError::SessionUnavailable)?,
        );
        // SAFETY: this native constructor transfers one cancellable reference.
        let cancellable = unsafe { ffi::g_cancellable_new() };
        self.pdf_exports
            .pending
            .borrow_mut()
            .insert(id, cancellable);
        let request = Box::new(Completion {
            registry: self.pdf_exports.clone(),
            hub: Rc::downgrade(&self.page_hub),
            id,
            finish: api.finish,
        });
        // SAFETY: the owner-thread session retains a live view and cancellable;
        // validated settings are copied, and the callback consumes its boxed state once.
        unsafe {
            (api.export)(
                self.web_view,
                id.get(),
                settings.paper_width,
                settings.paper_height,
                settings.margins[0],
                settings.margins[1],
                settings.margins[2],
                settings.margins[3],
                settings.scale,
                settings.first_page,
                settings.page_count.unwrap_or(0),
                i32::from(settings.print_backgrounds),
                cancellable,
                finished,
                Box::into_raw(request).cast(),
            );
        }
        Ok(id)
    }

    /// Cancel a pending export; its completion event reports cancellation.
    /// Returns false when the identity is not pending in this session.
    pub fn cancel_pdf_export(&self, id: PdfPrintId) -> bool {
        self.pdf_exports.cancel(id)
    }
}
