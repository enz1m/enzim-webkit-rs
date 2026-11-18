//! Leased WPEPlatform DMA-BUF frames without snapshot readback.

use super::runtime::WebSession;
use super::wpe;
use crate::frame_damage::{FrameContentInfo, FrameDamage};
use crate::web::{ViewId, ViewRouter};
use core::ffi::{c_int, c_uint, c_void};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak as SyncWeak};

#[repr(C)]
struct Rectangle {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
}

type Render = unsafe extern "C" fn(
    *mut wpe::WPEView,
    *mut wpe::WPEBuffer,
    *const Rectangle,
    c_uint,
    *mut *mut wpe::GError,
) -> wpe::GBoolean;

unsafe extern "C" {
    pub(super) fn enzui_wpe_observe_frames(view: *mut wpe::WPEView);
    fn enzui_wpe_rendered_frame_count(view: *mut wpe::WPEView) -> u64;
    fn enzui_wpe_buffer_identity(buffer: *mut wpe::WPEBuffer) -> u64;
    fn enzui_wpe_buffer_export_metadata(buffer: *mut wpe::WPEBuffer) -> *mut c_void;
    fn enzui_wpe_buffer_set_export_metadata(
        buffer: *mut wpe::WPEBuffer,
        data: *mut c_void,
        destroy: extern "C" fn(*mut c_void),
    );
    fn enzui_wpe_set_buffer_formats(
        view: *mut wpe::WPEView,
        formats: *const u32,
        modifiers: *const u64,
        count: c_uint,
    ) -> wpe::GBoolean;
    fn enzui_wpe_swap_render_buffer(view: *mut wpe::WPEView, replacement: Render)
    -> Option<Render>;
    fn wpe_buffer_dma_buf_get_type() -> wpe::GType;
    fn wpe_buffer_dma_buf_get_format(buffer: *mut wpe::WPEBuffer) -> u32;
    fn wpe_buffer_dma_buf_get_n_planes(buffer: *mut wpe::WPEBuffer) -> u32;
    fn wpe_buffer_dma_buf_get_modifier(buffer: *mut wpe::WPEBuffer) -> u64;
    fn wpe_buffer_dma_buf_get_fd(buffer: *mut wpe::WPEBuffer, plane: u32) -> c_int;
    fn wpe_buffer_dma_buf_get_offset(buffer: *mut wpe::WPEBuffer, plane: u32) -> u32;
    fn wpe_buffer_dma_buf_get_stride(buffer: *mut wpe::WPEBuffer, plane: u32) -> u32;
    fn wpe_buffer_get_width(buffer: *mut wpe::WPEBuffer) -> c_int;
    fn wpe_buffer_get_height(buffer: *mut wpe::WPEBuffer) -> c_int;
    fn wpe_buffer_get_display(buffer: *mut wpe::WPEBuffer) -> *mut wpe::WPEDisplay;
    fn wpe_buffer_import_to_egl_image(
        buffer: *mut wpe::WPEBuffer,
        error: *mut *mut wpe::GError,
    ) -> *mut c_void;
    fn wpe_display_get_egl_display(
        display: *mut wpe::WPEDisplay,
        error: *mut *mut wpe::GError,
    ) -> *mut c_void;
    fn wpe_view_buffer_rendered(view: *mut wpe::WPEView, buffer: *mut wpe::WPEBuffer);
    fn wpe_view_buffer_released(view: *mut wpe::WPEView, buffer: *mut wpe::WPEBuffer);
    fn wpe_view_set_visible(view: *mut wpe::WPEView, visible: wpe::GBoolean);
    fn wpe_view_get_visible(view: *mut wpe::WPEView) -> wpe::GBoolean;
    fn g_unix_fd_add_full(
        priority: c_int,
        fd: c_int,
        condition: c_uint,
        callback: extern "C" fn(c_int, c_uint, *mut c_void) -> wpe::GBoolean,
        data: *mut c_void,
        destroy: extern "C" fn(*mut c_void),
    ) -> c_uint;
}

thread_local! {
    static VIEWS: RefCell<HashMap<usize, Weak<State>>> = RefCell::new(HashMap::new());
    static ORIGINALS: RefCell<HashMap<usize, Option<Render>>> = RefCell::new(HashMap::new());
    static COMPLETION_OWNER: RefCell<Option<CompletionOwner>> = const { RefCell::new(None) };
}

/// Maximum compositor frames retained by a session and its GPU consumers.
pub const MAX_HELD_GPU_FRAMES: usize = 3;

static NEXT_CONTENT_STREAM: AtomicU64 = AtomicU64::new(1);

fn next_content_stream() -> u64 {
    NEXT_CONTENT_STREAM
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .unwrap_or(0)
}

struct State {
    content_stream: Cell<u64>,
    content_serial: Cell<u64>,
    content_extent: Cell<(u32, u32)>,
    active: Cell<usize>,
    deferred: RefCell<Option<Weak<Lease>>>,
    pending: RefCell<Option<Rc<Lease>>>,
    view_id: Cell<Option<ViewId>>,
}

struct Lease {
    content: FrameContentInfo,
    view: *mut wpe::WPEView,
    buffer: *mut wpe::WPEBuffer,
    presented: Cell<bool>,
    view_id: Option<ViewId>,
    state: Weak<State>,
}

impl Lease {
    fn acknowledge(&self) {
        if !self.presented.replace(true) {
            // SAFETY: this lease owns references to both objects on their native thread.
            unsafe { wpe_view_buffer_rendered(self.view, self.buffer) };
        }
    }

    fn request_presentation(self: &Rc<Self>) {
        if self.presented.get() {
            return;
        }
        if let Some(state) = self.state.upgrade()
            && state.active.get() >= MAX_HELD_GPU_FRAMES
        {
            state.deferred.replace(Some(Rc::downgrade(self)));
        } else {
            self.acknowledge();
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // A discarded frame must acknowledge completion to release producer backpressure.
        self.acknowledge();
        // SAFETY: the last consumer has finished; both owned references remain live until unref.
        unsafe {
            wpe_view_buffer_released(self.view, self.buffer);
            wpe::g_object_unref(self.buffer.cast());
            wpe::g_object_unref(self.view.cast());
        }
        if let Some(state) = self.state.upgrade() {
            state.active.set(state.active.get().saturating_sub(1));
            if state.active.get() < MAX_HELD_GPU_FRAMES {
                let deferred = state.deferred.take().and_then(|lease| lease.upgrade());
                if let Some(lease) = deferred {
                    lease.acknowledge();
                }
            }
        }
    }
}

unsafe extern "C" fn render(
    view: *mut wpe::WPEView,
    buffer: *mut wpe::WPEBuffer,
    damage: *const Rectangle,
    count: c_uint,
    error: *mut *mut wpe::GError,
) -> wpe::GBoolean {
    let state = VIEWS.with(|views| views.borrow().get(&(view as usize)).and_then(Weak::upgrade));
    if let Some(state) = state {
        // SAFETY: WPE calls its vfunc with live objects; these references outlive this callback.
        unsafe {
            wpe::g_object_ref(view.cast());
            wpe::g_object_ref(buffer.cast());
        }
        state.active.set(state.active.get() + 1);
        // SAFETY: the render callback retains the live buffer for the following dimension reads.
        let extent = unsafe { (wpe_buffer_get_width(buffer), wpe_buffer_get_height(buffer)) };
        let extent = (
            u32::try_from(extent.0).unwrap_or(0),
            u32::try_from(extent.1).unwrap_or(0),
        );
        let mut region = FrameDamage::Full;
        if !damage.is_null() && count > 0 && count <= 64 {
            // SAFETY: WPE supplies count valid rectangles only for the duration of this callback.
            let rectangles = unsafe { std::slice::from_raw_parts(damage, count as usize) };
            region = FrameDamage::from_rectangles(
                extent,
                rectangles.iter().map(|r| (r.x, r.y, r.width, r.height)),
            );
        }
        let serial = match state.content_serial.get().checked_add(1) {
            Some(serial) => serial,
            None => {
                state.content_stream.set(next_content_stream());
                1
            }
        };
        if state.content_extent.replace(extent) != extent {
            region = FrameDamage::Full;
        }
        state.content_serial.set(serial);
        let mut content = FrameContentInfo::new(state.content_stream.get(), serial, extent, region);
        if let Some(discarded) = state.pending.borrow().as_ref() {
            content.accumulate(discarded.content);
        }
        let pending = Rc::new(Lease {
            content,
            view,
            buffer,
            presented: Cell::new(false),
            view_id: state.view_id.get(),
            state: Rc::downgrade(&state),
        });
        // Drop outside the borrow because acknowledgment can dispatch another native callback.
        let discarded = state.pending.replace(Some(pending));
        drop(discarded);
        return wpe::G_TRUE;
    }
    // SAFETY: WPEView is GObject-derived and begins with its class pointer.
    let class = unsafe { *(view.cast::<*mut c_void>()) } as usize;
    let original = ORIGINALS.with(|originals| originals.borrow().get(&class).copied().flatten());
    match original {
        // SAFETY: forward the original callback's unchanged arguments on the same native thread.
        Some(original) => unsafe { original(view, buffer, damage, count, error) },
        None => wpe::G_FALSE,
    }
}

pub(super) struct PresentationBinding {
    view: *mut wpe::WPEView,
    state: Rc<State>,
}

impl PresentationBinding {
    pub(super) unsafe fn new(view: *mut wpe::WPEView, view_id: Option<ViewId>) -> Self {
        // SAFETY: the caller supplies this session's live GObject-derived view on its owning thread.
        let class = unsafe { *(view.cast::<*mut c_void>()) } as usize;
        ORIGINALS.with(|originals| {
            originals.borrow_mut().entry(class).or_insert_with(|| {
                // SAFETY: install once per class on the one native thread; C uses the SDK's layout.
                unsafe { enzui_wpe_swap_render_buffer(view, render) }
            });
        });
        let state = Rc::new(State {
            content_stream: Cell::new(next_content_stream()),
            content_serial: Cell::new(0),
            content_extent: Cell::new((0, 0)),
            active: Cell::new(0),
            deferred: RefCell::new(None),
            pending: RefCell::new(None),
            view_id: Cell::new(view_id),
        });
        VIEWS.with(|views| {
            views
                .borrow_mut()
                .insert(view as usize, Rc::downgrade(&state));
        });
        Self { view, state }
    }
}

impl PresentationBinding {
    pub(super) fn set_view(&self, view: ViewId) {
        self.state.view_id.set(Some(view));
        self.state.content_stream.set(next_content_stream());
        self.state.content_serial.set(0);
        let discarded = self.state.pending.take();
        drop(discarded);
    }
}

impl Drop for PresentationBinding {
    fn drop(&mut self) {
        VIEWS.with(|views| {
            views.borrow_mut().remove(&(self.view as usize));
        });
        let discarded = self.state.pending.take();
        drop(discarded);
    }
}

/// A native compositor frame could not be delivered or imported.
#[derive(Debug)]
#[non_exhaustive]
pub enum GpuFrameError {
    /// The request names a foreign or superseded view.
    WrongView,
    /// Direct compositor delivery has not been enabled.
    Disabled,
    /// A pending buffer predates the session's current binding.
    StaleGeneration,
    /// The compositor supplied a buffer without DMA-BUF planes.
    UnsupportedBuffer,
    /// Native dimensions, planes, or descriptors are invalid.
    InvalidBuffer,
    /// Duplicating a native descriptor failed.
    DuplicateDescriptor(std::io::Error),
    /// The cross-thread completion notification could not be installed.
    Completion(std::io::Error),
    /// The native display or driver refused EGL import.
    EglImport(String),
}

impl core::fmt::Display for GpuFrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongView => f.write_str("GPU frame does not belong to this live view"),
            Self::Disabled => f.write_str("GPU presentation is disabled"),
            Self::StaleGeneration => f.write_str("GPU frame belongs to an earlier view generation"),
            Self::UnsupportedBuffer => f.write_str("the compositor did not supply a DMA-BUF frame"),
            Self::InvalidBuffer => f.write_str("invalid DMA-BUF dimensions or plane descriptor"),
            Self::DuplicateDescriptor(error) => {
                write!(f, "DMA-BUF descriptor duplication failed: {error}")
            }
            Self::Completion(error) => write!(f, "GPU completion notification failed: {error}"),
            Self::EglImport(error) => write!(f, "GPU frame import failed: {error}"),
        }
    }
}

impl std::error::Error for GpuFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DuplicateDescriptor(error) | Self::Completion(error) => Some(error),
            _ => None,
        }
    }
}

/// A plane's owned descriptor and byte layout in the DMA-BUF allocation.
#[derive(Debug)]
pub struct DmaBufPlane {
    /// The allocation remains leased while its parent frame is alive.
    pub fd: OwnedFd,
    /// Byte offset from the start of the allocation.
    pub offset: u32,
    /// Bytes between successive rows.
    pub stride: u32,
}

/// A shared plane descriptor and immutable byte layout.
#[derive(Debug)]
pub struct SharedDmaBufPlane {
    /// Sharing the descriptor preserves the allocation, not its producer lease.
    pub fd: Arc<OwnedFd>,
    /// Byte offset from the start of the allocation.
    pub offset: u32,
    /// Bytes between successive rows.
    pub stride: u32,
}

/// Immutable metadata retained by its native allocation and any exported owners.
#[derive(Debug)]
pub struct GpuBufferMetadata {
    buffer_id: u64,
    size: (u32, u32),
    format: u32,
    modifier: u64,
    planes: Box<[SharedDmaBufPlane]>,
}

impl GpuBufferMetadata {
    /// Process-unique native allocation identity.
    pub fn buffer_id(&self) -> u64 {
        self.buffer_id
    }
    /// Physical allocation dimensions.
    pub fn size(&self) -> (u32, u32) {
        self.size
    }
    /// DRM fourcc pixel format.
    pub fn format(&self) -> u32 {
        self.format
    }
    /// DRM layout modifier shared by every plane.
    pub fn modifier(&self) -> u64 {
        self.modifier
    }
    /// Validated descriptors shared across exports of the allocation.
    pub fn planes(&self) -> &[SharedDmaBufPlane] {
        &self.planes
    }
}

impl Drop for GpuBufferMetadata {
    fn drop(&mut self) {
        METADATA_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// A cross-thread frame with shared allocation metadata and a fresh producer hold.
///
/// Retain the completion token through final GPU sampling. Metadata alone keeps
/// descriptors open but does not prevent producer writes to a reused allocation.
pub struct SharedGpuFrame {
    content: FrameContentInfo,
    view: ViewId,
    buffer: Arc<GpuBufferMetadata>,
    completion: GpuFrameCompletion,
}

impl SharedGpuFrame {
    /// Content serial and bounded physical-pixel damage, independent of allocation reuse.
    pub fn content_info(&self) -> FrameContentInfo {
        self.content
    }
    /// Exact source view generation.
    pub fn view(&self) -> ViewId {
        self.view
    }
    /// Process-unique native allocation identity.
    pub fn buffer_id(&self) -> u64 {
        self.buffer.buffer_id()
    }
    /// Shared immutable allocation metadata.
    pub fn buffer(&self) -> &Arc<GpuBufferMetadata> {
        &self.buffer
    }
    /// Move the allocation metadata and producer completion hold to the consumer.
    pub fn into_parts(self) -> (Arc<GpuBufferMetadata>, GpuFrameCompletion) {
        (self.buffer, self.completion)
    }
}

type RetainedGpuLease = (Rc<Lease>, Rc<State>);

struct OwnedBufferLayout {
    buffer_id: u64,
    width: u32,
    height: u32,
    format: u32,
    modifier: u64,
    planes: Vec<DmaBufPlane>,
}

/// A compositor frame that keeps its native buffers unavailable for reuse.
///
/// Import the planes into the host GPU and retain this frame until every GPU
/// read has completed. Call [`Self::presented`] when the host presents it.
/// Dropping an unpresented frame discards it and resumes the producer. Native
/// ownership confines this value to the session's thread.
pub struct DmaBufFrame {
    buffer_id: u64,
    view: ViewId,
    width: u32,
    height: u32,
    format: u32,
    modifier: u64,
    planes: Vec<DmaBufPlane>,
    lease: Rc<Lease>,
    _state: Rc<State>,
}

impl DmaBufFrame {
    /// Content serial and bounded physical-pixel damage.
    pub fn content_info(&self) -> FrameContentInfo {
        self.lease.content
    }
    /// Process-unique allocation identity, stable across reuse of this buffer.
    /// Cache GPU imports by this ID with a bounded eviction policy; a new native
    /// allocation receives a new ID even if its pointer or descriptors are reused.
    pub fn buffer_id(&self) -> u64 {
        self.buffer_id
    }

    /// The exact view generation that supplied this frame.
    pub fn view(&self) -> ViewId {
        self.view
    }
    /// Physical pixel dimensions.
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
    /// DRM fourcc pixel format.
    pub fn format(&self) -> u32 {
        self.format
    }
    /// DRM layout modifier shared by every plane.
    pub fn modifier(&self) -> u64 {
        self.modifier
    }
    /// Plane descriptors, owned until this frame drops.
    pub fn planes(&self) -> &[DmaBufPlane] {
        &self.planes
    }
    /// Acknowledge presentation once, allowing the next frame to be produced.
    /// The current buffer remains leased until this frame drops. At the
    /// three-frame bound, acknowledgment waits until another frame is released.
    pub fn presented(&self) {
        self.lease.request_presentation();
    }

    /// Import this frame into its WPE display as a borrowed EGLImage.
    ///
    /// The returned display and image remain valid while this frame is alive;
    /// the caller must not destroy them. GPU consumers must finish before the
    /// frame drops. The display uses implicit synchronization: WPE waits for
    /// the rendering fence before handing the frame to the platform.
    ///
    /// # Errors
    /// Returns an error when the display or driver cannot import the buffer.
    pub fn egl_image(&self) -> Result<(*mut c_void, *mut c_void), GpuFrameError> {
        let mut error = std::ptr::null_mut();
        // SAFETY: the lease retains the live buffer and its owning display on this thread.
        let display = unsafe {
            wpe_display_get_egl_display(wpe_buffer_get_display(self.lease.buffer), &mut error)
        };
        if display.is_null() {
            return Err(GpuFrameError::EglImport(native_error(
                error,
                "EGL display unavailable",
            )));
        }
        // SAFETY: the native buffer remains leased; WPE owns and caches the resulting EGLImage.
        let image = unsafe { wpe_buffer_import_to_egl_image(self.lease.buffer, &mut error) };
        if image.is_null() {
            return Err(GpuFrameError::EglImport(native_error(
                error,
                "DMA-BUF EGL import failed",
            )));
        }
        Ok((display, image))
    }
}

struct CompletionSignal {
    fd: Arc<OwnedFd>,
    presented: AtomicBool,
}

impl CompletionSignal {
    /// Has the native owner act on this signal: at once when called on that
    /// thread outside a completion pass, otherwise on its next dispatch.
    fn notify(&self) {
        if self.complete_on_owner() {
            return;
        }
        while let Err(rustix::io::Errno::INTR) = rustix::io::write(&self.fd, &1_u64.to_ne_bytes()) {
        }
    }

    /// Runs the completion pass now if this thread owns the signal's hub and
    /// no pass is running. A signal raised inside a pass is left to the
    /// descriptor: the pass may already have visited its frame.
    fn complete_on_owner(&self) -> bool {
        // The slot is gone while the thread's locals are destroyed, and
        // borrowed while its owner is created.
        let hub = COMPLETION_OWNER
            .try_with(|slot| {
                slot.try_borrow()
                    .ok()
                    .and_then(|owner| owner.as_ref().map(|owner| Rc::clone(&owner.hub)))
            })
            .ok()
            .flatten();
        match hub {
            Some(hub) if Arc::ptr_eq(&hub.fd, &self.fd) => hub.complete(),
            _ => false,
        }
    }
}

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        self.notify();
    }
}

/// A cross-thread presentation acknowledgment and hold on a native frame.
///
/// Keep a clone until GPU sampling finishes. The last clone releases the
/// buffer on its owning thread, even after the session is dropped: at once
/// when it is dropped there, otherwise by waking the native context, which
/// that thread must continue pumping.
#[derive(Clone)]
pub struct GpuFrameCompletion(Arc<CompletionSignal>);

impl std::fmt::Debug for GpuFrameCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GpuFrameCompletion(..)")
    }
}

impl GpuFrameCompletion {
    /// Acknowledge presentation on the native owner thread: at once when
    /// called there, otherwise on its next dispatch.
    pub fn presented(&self) {
        if !self.0.presented.swap(true, Ordering::AcqRel) {
            self.0.notify();
        }
    }
}

struct NativeFrameHold {
    lease: Rc<Lease>,
    _state: Rc<State>,
}

impl NativeFrameHold {
    fn presented(&self) {
        self.lease.request_presentation();
    }
}

struct DeferredFrame {
    frame: NativeFrameHold,
    completion: SyncWeak<CompletionSignal>,
}

static COMPLETION_SOURCES: AtomicU64 = AtomicU64::new(0);
static COMPLETION_EXPORTS: AtomicU64 = AtomicU64::new(0);
static PLANE_DUPLICATIONS: AtomicU64 = AtomicU64::new(0);
static METADATA_CREATED: AtomicU64 = AtomicU64::new(0);
static METADATA_DROPPED: AtomicU64 = AtomicU64::new(0);
static METADATA_HITS: AtomicU64 = AtomicU64::new(0);

/// Cumulative successful allocations in the compositor export path.
#[derive(Clone, Copy, Debug)]
pub struct GpuTransportCounters {
    /// GLib wake sources allocated for consumer completion dispatch.
    pub completion_sources: u64,
    /// Frames transferred to consumers on other threads.
    pub completion_exports: u64,
    /// Owned plane descriptors duplicated from native buffers.
    pub plane_duplications: u64,
    /// Native allocation metadata objects constructed after full validation.
    pub metadata_created: u64,
    /// Metadata objects whose final shared owner has dropped.
    pub metadata_dropped: u64,
    /// Exports reusing an allocation's existing metadata.
    pub metadata_hits: u64,
}

/// Read monotonic compositor transport counters without resetting other consumers.
pub fn gpu_transport_counters() -> GpuTransportCounters {
    GpuTransportCounters {
        completion_sources: COMPLETION_SOURCES.load(Ordering::Relaxed),
        completion_exports: COMPLETION_EXPORTS.load(Ordering::Relaxed),
        plane_duplications: PLANE_DUPLICATIONS.load(Ordering::Relaxed),
        metadata_created: METADATA_CREATED.load(Ordering::Relaxed),
        metadata_dropped: METADATA_DROPPED.load(Ordering::Relaxed),
        metadata_hits: METADATA_HITS.load(Ordering::Relaxed),
    }
}

static PENDING_COMPLETIONS: AtomicUsize = AtomicUsize::new(0);

/// Exported frames whose final consumer release still needs native dispatch.
/// A native main-loop host can keep pumping until this reaches zero on close.
pub fn pending_gpu_frame_completions() -> usize {
    PENDING_COMPLETIONS.load(Ordering::Acquire)
}

struct CompletionHub {
    fd: Arc<OwnedFd>,
    frames: RefCell<Vec<DeferredFrame>>,
    owner_alive: Cell<bool>,
    /// A completion pass is running on the owner thread.
    completing: Cell<bool>,
}

impl CompletionHub {
    /// Acknowledges every frame marked presented and releases every frame
    /// whose last completion clone is gone. Returns `false`, having done
    /// nothing, when called from inside a pass.
    fn complete(&self) -> bool {
        if self.completing.replace(true) {
            return false;
        }
        // Native acknowledgements can reenter export; no registry borrow crosses them.
        let mut frames = self.frames.take();
        let before = frames.len();
        frames.retain(|deferred| {
            let Some(completion) = deferred.completion.upgrade() else {
                return false;
            };
            if completion.presented.load(Ordering::Acquire) {
                deferred.frame.presented();
            }
            true
        });
        PENDING_COMPLETIONS.fetch_sub(before - frames.len(), Ordering::AcqRel);
        let added = self.frames.replace(frames);
        self.frames.borrow_mut().extend(added);
        self.completing.set(false);
        true
    }
}

struct CompletionOwner {
    hub: Rc<CompletionHub>,
    source: c_uint,
}

impl CompletionOwner {
    fn new() -> Result<Self, GpuFrameError> {
        let fd = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .map_err(|error| GpuFrameError::Completion(error.into()))?;
        let hub = Rc::new(CompletionHub {
            fd: Arc::new(fd),
            frames: RefCell::new(Vec::new()),
            owner_alive: Cell::new(true),
            completing: Cell::new(false),
        });
        let data = Rc::into_raw(Rc::clone(&hub));
        // SAFETY: the source owns this Rc and its descriptor until its owner-thread destroy callback.
        let source = unsafe {
            g_unix_fd_add_full(
                0,
                hub.fd.as_raw_fd(),
                1,
                complete_frames,
                data.cast_mut().cast(),
                destroy_completion_hub,
            )
        };
        if source == 0 {
            // GLib destroys its callback data even when source attachment fails.
            return Err(GpuFrameError::Completion(std::io::Error::other(
                "GLib completion source attachment failed",
            )));
        }
        COMPLETION_SOURCES.fetch_add(1, Ordering::Relaxed);
        Ok(Self { hub, source })
    }
}

impl Drop for CompletionOwner {
    fn drop(&mut self) {
        self.hub.owner_alive.set(false);
        if self.hub.frames.borrow().is_empty() {
            // SAFETY: this owner removes its still-attached source on the native thread.
            unsafe { wpe::g_source_remove(self.source) };
        }
    }
}

fn completion_hub() -> Result<Rc<CompletionHub>, GpuFrameError> {
    COMPLETION_OWNER.with(|slot| {
        let mut owner = slot.borrow_mut();
        if owner.is_none() {
            *owner = Some(CompletionOwner::new()?);
        }
        Ok(Rc::clone(
            &owner.as_ref().expect("initialized completion owner").hub,
        ))
    })
}

extern "C" fn complete_frames(_fd: c_int, _condition: c_uint, data: *mut c_void) -> wpe::GBoolean {
    // SAFETY: the attached source retains this hub and dispatches on the native owner.
    let hub = unsafe { &*data.cast::<CompletionHub>() };
    let mut counter = [0_u8; 8];
    while matches!(
        rustix::io::read(&hub.fd, &mut counter),
        Err(rustix::io::Errno::INTR)
    ) {}
    if !hub.complete() {
        // Dispatched inside a pass, which may be past the frames these wakes
        // were for: they are raised again for the dispatch after it.
        while let Err(rustix::io::Errno::INTR) = rustix::io::write(&hub.fd, &1_u64.to_ne_bytes()) {}
        return wpe::G_TRUE;
    }
    if !hub.owner_alive.get() && hub.frames.borrow().is_empty() {
        wpe::G_FALSE
    } else {
        wpe::G_TRUE
    }
}

extern "C" fn destroy_completion_hub(data: *mut c_void) {
    // SAFETY: source removal transfers its one Rc back on the native owner thread.
    drop(unsafe { Rc::from_raw(data.cast::<CompletionHub>()) });
}

/// Owned DMA-BUF metadata transferable to another thread without native objects.
///
/// Use the completion token to retain the native producer lease through GPU
/// sampling. Plane descriptors alone do not keep a producer from reusing memory.
pub struct ThreadSafeGpuFrame {
    content: FrameContentInfo,
    buffer_id: u64,
    view: ViewId,
    size: (u32, u32),
    format: u32,
    modifier: u64,
    planes: Vec<DmaBufPlane>,
    completion: GpuFrameCompletion,
}

impl ThreadSafeGpuFrame {
    /// Content serial and bounded physical-pixel damage.
    pub fn content_info(&self) -> FrameContentInfo {
        self.content
    }
    /// Process-unique allocation identity, stable across buffer reuse.
    pub fn buffer_id(&self) -> u64 {
        self.buffer_id
    }
    /// Exact source view generation.
    pub fn view(&self) -> ViewId {
        self.view
    }
    /// Physical pixel dimensions.
    pub fn size(&self) -> (u32, u32) {
        self.size
    }
    /// DRM fourcc pixel format.
    pub fn format(&self) -> u32 {
        self.format
    }
    /// DRM layout modifier.
    pub fn modifier(&self) -> u64 {
        self.modifier
    }
    /// Move the plane descriptors and producer completion hold to the consumer.
    pub fn into_parts(self) -> (Vec<DmaBufPlane>, GpuFrameCompletion) {
        (self.planes, self.completion)
    }
}

impl DmaBufFrame {
    /// Export descriptors and a completion hold for a consumer on another thread.
    ///
    /// Native references stay on this thread behind a shared eventfd-backed GLib source.
    /// There is no polling timer; presentation and final release wake the source.
    /// Continue pumping the native context until all consumer holds are released.
    ///
    /// # Errors
    /// Returns an error if the owner notification descriptor or source cannot be allocated.
    pub fn into_thread_safe(self) -> Result<ThreadSafeGpuFrame, GpuFrameError> {
        let size = self.size();
        let content = self.content_info();
        let completion = export_completion(self.lease, self._state)?;
        Ok(ThreadSafeGpuFrame {
            content,
            buffer_id: self.buffer_id,
            view: self.view,
            size,
            format: self.format,
            modifier: self.modifier,
            planes: self.planes,
            completion,
        })
    }
}

fn export_completion(
    lease: Rc<Lease>,
    state: Rc<State>,
) -> Result<GpuFrameCompletion, GpuFrameError> {
    let hub = completion_hub()?;
    let completion = Arc::new(CompletionSignal {
        fd: Arc::clone(&hub.fd),
        presented: AtomicBool::new(false),
    });
    hub.frames.borrow_mut().push(DeferredFrame {
        frame: NativeFrameHold {
            lease,
            _state: state,
        },
        completion: Arc::downgrade(&completion),
    });
    PENDING_COMPLETIONS.fetch_add(1, Ordering::AcqRel);
    COMPLETION_EXPORTS.fetch_add(1, Ordering::Relaxed);
    Ok(GpuFrameCompletion(completion))
}

extern "C" fn destroy_export_metadata(data: *mut c_void) {
    // SAFETY: the native allocation transfers its boxed Arc exactly once; it contains no native objects.
    drop(unsafe { Box::from_raw(data.cast::<Arc<GpuBufferMetadata>>()) });
}

fn read_buffer_layout(lease: &Lease) -> Result<OwnedBufferLayout, GpuFrameError> {
    // SAFETY: the checked live DMA-BUF owns every returned descriptor for this lease's lifetime.
    let (width, height, format, modifier, count) = unsafe {
        (
            wpe_buffer_get_width(lease.buffer),
            wpe_buffer_get_height(lease.buffer),
            wpe_buffer_dma_buf_get_format(lease.buffer),
            wpe_buffer_dma_buf_get_modifier(lease.buffer),
            wpe_buffer_dma_buf_get_n_planes(lease.buffer),
        )
    };
    if width <= 0 || height <= 0 || !(1..=4).contains(&count) {
        return Err(GpuFrameError::InvalidBuffer);
    }
    let mut planes = Vec::with_capacity(count as usize);
    for plane in 0..count {
        // SAFETY: every queried plane is below the native plane count.
        let (fd, offset, stride) = unsafe {
            (
                wpe_buffer_dma_buf_get_fd(lease.buffer, plane),
                wpe_buffer_dma_buf_get_offset(lease.buffer, plane),
                wpe_buffer_dma_buf_get_stride(lease.buffer, plane),
            )
        };
        if fd < 0 || stride == 0 {
            return Err(GpuFrameError::InvalidBuffer);
        }
        // SAFETY: this descriptor is borrowed from the live native buffer, never closed here.
        let fd = unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .map_err(GpuFrameError::DuplicateDescriptor)?;
        PLANE_DUPLICATIONS.fetch_add(1, Ordering::Relaxed);
        planes.push(DmaBufPlane { fd, offset, stride });
    }
    // SAFETY: the live native allocation owns its identity for its full GObject lifetime.
    let buffer_id = unsafe { enzui_wpe_buffer_identity(lease.buffer) };
    if buffer_id == 0 {
        return Err(GpuFrameError::InvalidBuffer);
    }
    Ok(OwnedBufferLayout {
        buffer_id,
        width: width as u32,
        height: height as u32,
        format,
        modifier,
        planes,
    })
}

fn native_error(error: *mut wpe::GError, fallback: &str) -> String {
    if error.is_null() {
        return fallback.to_owned();
    }
    // SAFETY: the failed native call returned an owned GError.
    let message = unsafe {
        crate::native_diagnostic::read_bounded_diagnostic(
            (*error).message,
            crate::native_diagnostic::MAX_NATIVE_DIAGNOSTIC_BYTES,
        )
    };
    // SAFETY: this error belongs to the caller and is freed exactly once.
    unsafe { wpe::g_error_free(error) };
    message
}

impl WebSession {
    /// Advertise the consumer's supported DMA-BUF layouts to this live view.
    ///
    /// WPE intersects these preferences with its allocator's capabilities.
    /// An empty list restores platform defaults. Existing exported buffers
    /// retain their original layout until released.
    /// Returns false for a stale view, absent native toplevel, or over 4096 layouts.
    pub fn set_gpu_buffer_formats(
        &self,
        router: &ViewRouter,
        view: ViewId,
        formats: &[(u32, Vec<u64>)],
    ) -> bool {
        if self.bound_view() != Some(view) || !router.accepts(view) {
            return false;
        }
        let count: usize = formats.iter().map(|(_, modifiers)| modifiers.len()).sum();
        if count > 4096 {
            return false;
        }
        let mut fourccs = Vec::with_capacity(count);
        let mut modifiers = Vec::with_capacity(count);
        for (format, supported) in formats {
            fourccs.extend(std::iter::repeat_n(*format, supported.len()));
            modifiers.extend_from_slice(supported);
        }
        // SAFETY: parallel arrays remain live for the synchronous copy on the native owner thread.
        unsafe {
            enzui_wpe_set_buffer_formats(
                self.wpe_view,
                fourccs.as_ptr(),
                modifiers.as_ptr(),
                count as u32,
            ) != wpe::G_FALSE
        }
    }

    /// Return future buffers to the headless presenter; exported holds remain valid.
    pub fn disable_gpu_presentation(&mut self) {
        self.gpu_presentation = None;
    }

    /// Set native page visibility for this live view; refuse foreign or stale views.
    /// Hidden pages stop producing visible compositor updates and throttle animation.
    pub fn set_view_visibility(&self, router: &ViewRouter, view: ViewId, visible: bool) -> bool {
        if self.bound_view() != Some(view) || !router.accepts(view) {
            return false;
        }
        // SAFETY: the session retains its native view on the owning thread.
        unsafe { wpe_view_set_visible(self.wpe_view, i32::from(visible)) };
        true
    }

    /// Compositor buffers acknowledged by the active presenter since construction.
    /// The default headless presenter acknowledges at its frame timer; GPU
    /// consumers acknowledge through [`DmaBufFrame::presented`]. This counts
    /// native completion signals, not actual monitor scanout.
    pub fn acknowledged_frames(&self) -> u64 {
        // SAFETY: this session owns the observed native view on its initialization thread.
        unsafe { enzui_wpe_rendered_frame_count(self.wpe_view) }
    }

    /// Receive compositor buffers directly instead of reading back snapshots.
    ///
    /// Presentation follows the host's acknowledgments; an unconsumed frame
    /// stops further compositor output. This is intended for native GPU
    /// consumers. Snapshot users should keep the default headless presenter.
    pub fn enable_gpu_presentation(&mut self) {
        if self.gpu_presentation.is_none() {
            // SAFETY: this session owns the view and cannot leave its initialization thread.
            self.gpu_presentation =
                Some(unsafe { PresentationBinding::new(self.wpe_view, self.bound_view()) });
        }
    }

    /// Drop a hidden view's untaken frame, which holds a compositor buffer.
    pub(super) fn discard_hidden_gpu_frame(&self) {
        let Some(binding) = &self.gpu_presentation else {
            return;
        };
        // SAFETY: the session retains its native view on the owning thread.
        if unsafe { wpe_view_get_visible(self.wpe_view) } != wpe::G_FALSE {
            return;
        }
        let discarded = binding.state.pending.take();
        drop(discarded);
    }

    /// Whether a compositor buffer is waiting for this session's consumer.
    /// Pump the native context before using this to schedule a host redraw.
    pub fn gpu_frame_pending(&self) -> bool {
        self.gpu_presentation
            .as_ref()
            .is_some_and(|binding| binding.state.pending.borrow().is_some())
    }

    /// Take the pending DMA-BUF frame belonging to this live view generation.
    ///
    /// `None` means no pending frame. This performs descriptor duplication,
    /// never pixel readback. Pump the session to receive compositor callbacks.
    ///
    /// # Errors
    /// Rejects stale or foreign views, a disabled presenter, unsupported native
    /// buffer types, invalid dimensions/planes, and descriptor duplication failures.
    pub fn take_gpu_frame(
        &self,
        router: &ViewRouter,
        view: ViewId,
    ) -> Result<Option<DmaBufFrame>, GpuFrameError> {
        let Some((lease, state)) = self.take_gpu_lease(router, view)? else {
            return Ok(None);
        };
        let layout = read_buffer_layout(&lease)?;
        Ok(Some(DmaBufFrame {
            buffer_id: layout.buffer_id,
            view,
            width: layout.width,
            height: layout.height,
            format: layout.format,
            modifier: layout.modifier,
            planes: layout.planes,
            lease,
            _state: state,
        }))
    }

    /// Export a compositor frame using metadata shared for the native allocation's lifetime.
    ///
    /// Buffer layout is immutable in WPE; its first export validates and duplicates
    /// descriptors. Native allocation destruction retires its metadata association.
    /// Every export has its own completion hold, independent of shared descriptors.
    /// Continue native dispatch until all completion holds have been released.
    ///
    /// # Errors
    /// Returns the same view, buffer and descriptor errors as [`Self::take_gpu_frame`],
    /// or a completion notification allocation error.
    pub fn take_shared_gpu_frame(
        &self,
        router: &ViewRouter,
        view: ViewId,
    ) -> Result<Option<SharedGpuFrame>, GpuFrameError> {
        let Some((lease, state)) = self.take_gpu_lease(router, view)? else {
            return Ok(None);
        };
        // SAFETY: the owned lease prevents native allocation destruction throughout this lookup.
        let cached = unsafe { enzui_wpe_buffer_export_metadata(lease.buffer) };
        let buffer = if cached.is_null() {
            let layout = read_buffer_layout(&lease)?;
            let buffer = Arc::new(GpuBufferMetadata {
                buffer_id: layout.buffer_id,
                size: (layout.width, layout.height),
                format: layout.format,
                modifier: layout.modifier,
                planes: layout
                    .planes
                    .into_iter()
                    .map(|plane| SharedDmaBufPlane {
                        fd: Arc::new(plane.fd),
                        offset: plane.offset,
                        stride: plane.stride,
                    })
                    .collect(),
            });
            let data = Box::into_raw(Box::new(Arc::clone(&buffer)));
            // SAFETY: the native object owns the box until its destroy callback; no native object is retained by the metadata.
            unsafe {
                enzui_wpe_buffer_set_export_metadata(
                    lease.buffer,
                    data.cast(),
                    destroy_export_metadata,
                )
            };
            METADATA_CREATED.fetch_add(1, Ordering::Relaxed);
            buffer
        } else {
            METADATA_HITS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: this allocation's private data is the boxed Arc installed above, still protected by the lease.
            Arc::clone(unsafe { &*cached.cast::<Arc<GpuBufferMetadata>>() })
        };
        let content = lease.content;
        let completion = export_completion(lease, state)?;
        Ok(Some(SharedGpuFrame {
            content,
            view,
            buffer,
            completion,
        }))
    }

    fn take_gpu_lease(
        &self,
        router: &ViewRouter,
        view: ViewId,
    ) -> Result<Option<RetainedGpuLease>, GpuFrameError> {
        if !router.accepts(view) {
            return Err(GpuFrameError::WrongView);
        }
        if self.bound_view() != Some(view) {
            // The bound inspector frontend presents through its own binding.
            if self.inspector_target(view).is_none() {
                return Err(GpuFrameError::WrongView);
            }
            let inspector = self.inspector.borrow();
            let binding = &inspector.as_ref().expect("checked above").presentation;
            return Self::lease_from(binding, view);
        }
        let binding = self
            .gpu_presentation
            .as_ref()
            .ok_or(GpuFrameError::Disabled)?;
        Self::lease_from(binding, view)
    }

    fn lease_from(
        binding: &PresentationBinding,
        view: ViewId,
    ) -> Result<Option<RetainedGpuLease>, GpuFrameError> {
        let Some(lease) = binding.state.pending.take() else {
            return Ok(None);
        };
        if lease.view_id != Some(view) {
            return Err(GpuFrameError::StaleGeneration);
        }
        // SAFETY: the lease owns a live GObject-derived buffer; checked before DMA-BUF-specific calls.
        if unsafe {
            wpe::g_type_check_instance_is_a(lease.buffer.cast(), wpe_buffer_dma_buf_get_type())
        } == wpe::G_FALSE
        {
            return Err(GpuFrameError::UnsupportedBuffer);
        }
        Ok(Some((lease, Rc::clone(&binding.state))))
    }
}
