//! Thread-affine WPE displays, shared buffers, page sessions, and CPU snapshots.
//!
//! Native construction enforces sandbox, profile, and destination policies.
//! GPU consumers can enable [`WebSession::enable_gpu_presentation`] and receive
//! leased compositor buffers through [`WebSession::take_gpu_frame`].

use crate::ffi::wpe as ffi;
use crate::frame::{
    Generation, Rgba8Frame, RgbaGeometry, RgbaGeometryError, preflight_rgba8,
    preflight_rgba8_storage,
};
use crate::frame_plan::FrameSeq;
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::marker::PhantomData;
use enzui_security::decode_limits::DecodeLimits;
use std::ffi::CString;
use std::ptr;
use std::rc::Rc;

/// Why a [`HeadlessDisplay`] could not be constructed.
///
/// # Compatibility
///
/// `#[non_exhaustive]`: more environmental refusals may be distinguished over
/// time, and every variant means "no display was constructed", so a downstream
/// wildcard arm fails in the safe direction.
#[derive(Debug)]
#[non_exhaustive]
pub enum DisplayError {
    /// Native WPE initialization was attempted on an unsupported thread.
    WrongThread(crate::ffi::NativeThreadError),
    /// `wpe_display_headless_new()` returned NULL - the WPE runtime linked, but
    /// its `wpe-platform-headless` plugin could not be loaded at run time. A
    /// host can degrade or report it.
    HeadlessPluginUnavailable,
    /// The mandatory WebProcess request extension could not be configured
    /// before WPE initialized, so no display was constructed.
    CredentialGuardUnavailable(String),
}

/// A safe, RAII owner of a `WPEDisplay*` on the headless platform plugin.
///
/// Constructing this loads the real WPE runtime. On an environmental failure
/// (the headless plugin cannot be loaded) it returns a typed
/// [`DisplayError`] - never a silent mock substitution - because the caller
/// asked for the real thing (feature `wpe` is on) and there is no honest
/// fallback.
pub struct HeadlessDisplay {
    ptr: *mut ffi::WPEDisplay,
    /// A raw-pointer PhantomData so `HeadlessDisplay` is `!Send + !Sync` on
    /// stable Rust (the WPE runtime is thread-affine - GMainContext bound to
    /// the thread that constructed it). Negative bounds are unstable.
    _not_send_sync: PhantomData<*const c_void>,
}

/// Input devices forwarded by the host to views sharing a display.
/// Defaults to a desktop mouse and keyboard without a touchscreen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayInputDevices {
    /// Whether the host forwards mouse motion and buttons.
    pub mouse: bool,
    /// Whether the host forwards physical keyboard input.
    pub keyboard: bool,
    /// Whether the host forwards touchscreen input.
    pub touchscreen: bool,
}

impl Default for DisplayInputDevices {
    fn default() -> Self {
        Self {
            mouse: true,
            keyboard: true,
            touchscreen: false,
        }
    }
}

impl HeadlessDisplay {
    /// Construct a headless display with mouse and keyboard capabilities.
    ///
    /// # Errors
    ///
    /// [`DisplayError::HeadlessPluginUnavailable`] if
    /// `wpe_display_headless_new()` returns NULL, or
    /// [`DisplayError::CredentialGuardUnavailable`] if the mandatory
    /// WebProcess extension cannot be configured before WPE initialization.
    /// [`DisplayError::WrongThread`] if another thread owns native WPE or
    /// this runtime requires the process main thread.
    /// The first native initialization attempt retains ownership for the
    /// process lifetime, even on failure.
    pub fn new() -> Result<HeadlessDisplay, DisplayError> {
        Self::new_with_input_devices(DisplayInputDevices::default())
    }

    /// Construct a display with the host's available input devices.
    ///
    /// The declaration controls pointer and hover media queries for views
    /// sharing the display. It does not create devices or forward events.
    /// WebKit derives process-wide capabilities from WPE's primary display.
    ///
    /// # Errors
    /// Returns the initialization errors documented by [`Self::new`].
    pub fn new_with_input_devices(devices: DisplayInputDevices) -> Result<Self, DisplayError> {
        crate::ffi::threading::claim().map_err(DisplayError::WrongThread)?;
        // WebKit freezes sandbox paths as soon as its first subprocess starts;
        // Configure the pre-normalization request-guard extension before the WPE display can
        // cause process-global initialization.
        session_lifecycle::configure_credential_guard_extension()
            .map_err(DisplayError::CredentialGuardUnavailable)?;
        // SAFETY: `wpe_display_headless_new` takes no arguments and returns
        // either a `WPEDisplay*` with ref-count 1 or NULL. `from_raw` takes
        // ownership of that pointer (or maps NULL to a typed error).
        let ptr = unsafe { ffi::wpe_display_headless_new() };
        // SAFETY: `ptr` is a fresh owned `WPEDisplay*` (rc=1) or NULL.
        let display = unsafe { Self::from_raw(ptr) }?;
        display.set_input_devices(devices);
        Ok(display)
    }

    /// Update this display's host device declaration.
    ///
    /// Changes from WPE's primary display update live pointer and hover styles.
    /// Touch-event DOM attributes
    /// reflect the declaration when each document creates its window.
    /// Live style invalidation and device-based touch attributes require the
    /// reviewed source runtime; other runtimes retain their native behavior.
    pub fn set_input_devices(&self, devices: DisplayInputDevices) {
        let flags = u32::from(devices.mouse)
            | (u32::from(devices.keyboard) << 1)
            | (u32::from(devices.touchscreen) << 2);
        // SAFETY: this owner retains a live display on its native thread;
        // the flags match WPEAvailableInputDevices in WPEDisplay.h.
        unsafe { ffi::wpe_display_set_available_input_devices(self.ptr, flags) };
    }

    /// Wrap an owned `WPEDisplay*`, mapping NULL to a typed [`DisplayError`].
    ///
    /// This is the pure error-mapping seam split out of [`new`](Self::new)
    ///: passing a NULL pointer exercises the missing-plugin branch
    /// without a live WPE runtime, so the typed-error conversion is testable at
    /// the seam. A non-NULL pointer is adopted with ref-count semantics
    /// identical to `new` - dropped through `g_object_unref` in `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` must be either NULL or a `WPEDisplay*` with ref-count >= 1 that
    /// this owner may release exactly once. NULL is safe and returns `Err`
    /// without constructing anything.
    unsafe fn from_raw(ptr: *mut ffi::WPEDisplay) -> Result<HeadlessDisplay, DisplayError> {
        if ptr.is_null() {
            return Err(DisplayError::HeadlessPluginUnavailable);
        }
        Ok(HeadlessDisplay {
            ptr,
            _not_send_sync: PhantomData,
        })
    }

    /// The raw display pointer, for handing to another FFI call.
    #[must_use]
    pub fn as_ptr(&self) -> *mut ffi::WPEDisplay {
        self.ptr
    }
}

// `HeadlessDisplay` is intentionally not Send/Sync: the `_not_send_sync`
// PhantomData carries a raw pointer, which is neither. The WPE runtime is
// thread-affine via GMainContext.

/// A safe wrapper around a `WPEBufferSHM*` owned here.
///
/// The buffer holds a reference to a `GBytes` handed it; on drop this code unrefs
/// the buffer, and glib drops the `GBytes` with it.
pub struct SharedBuffer {
    ptr: *mut ffi::WPEBufferSHM,
    /// The `GBytes` constructed for the buffer's data. Held here for
    /// lifetime management: the WPE buffer borrows it, and glib will unref it
    /// when the last reference (this one or the buffer's) is dropped.
    ///
    /// After `wpe_buffer_shm_new`, this code drops OUR reference in the constructor,
    /// so the buffer holds the sole reference thereafter. This field is a
    /// null placeholder to make the ownership story explicit; the actual glib
    /// reference is owned by the buffer.
    _pixels_owned_by_buffer: (),
}

/// Copy a borrowed `GBytes` payload into Rust-owned storage.
///
/// # Safety
///
/// When `size > 0` and `data` is non-NULL, it must point to `size`
/// initialized, readable bytes. NULL is accepted so this helper can preserve
/// the native-boundary panic; no pointer validity requirement applies when
/// `size == 0`.
unsafe fn shared_buffer_payload(data: *const c_void, size: usize) -> Vec<u8> {
    if size == 0 {
        return Vec::new();
    }

    let data = ptr::NonNull::new(data.cast::<u8>().cast_mut())
        .unwrap_or_else(|| panic!("g_bytes_get_data() returned NULL for {size} bytes"));
    let mut out = vec![0; size];
    // SAFETY: the caller guarantees that non-NULL `data` points to `size`
    // initialized, readable bytes, and `out` has exactly `size` writable bytes.
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out.as_mut_ptr(), size) };
    out
}

impl SharedBuffer {
    /// Wrap `pixels` (a `Vec<u8>` of exactly `height * stride` `B,G,R,A`
    /// storage bytes on little-endian) as a `WPEBufferSHM` on the given display.
    ///
    /// # Panics
    ///
    /// Panics if the FFI returns NULL (e.g. width/height out of range for the
    /// WPE Platform's own checks). Feature is on, caller wanted the real path,
    /// no silent fallback.
    #[must_use]
    pub fn new_argb8888(
        display: &HeadlessDisplay,
        width: u32,
        height: u32,
        stride: u32,
        pixels: Vec<u8>,
    ) -> SharedBuffer {
        // WPEBufferSHM owns and copies complete rows, including padding after
        // the final row. Bound that full `height * stride` storage before
        // `g_bytes_new` can perform its native copy. This is intentionally
        // stricter than the borrowed-reader extent accepted by snapshots.
        let (_, storage_len) =
            preflight_rgba8_storage(width, height, u64::from(stride), &DecodeLimits::DEFAULT)
                .expect("SharedBuffer full storage must pass RGBA preflight before native copy");
        assert_eq!(
            pixels.len(),
            storage_len,
            "SharedBuffer::new_argb8888 requires exactly `height * stride` bytes; \
             got {} for a {}x{} @ stride {}",
            pixels.len(),
            width,
            height,
            stride,
        );

        // SAFETY: `g_bytes_new` copies `size` bytes from `data`. This code hands it the
        // Vec's pointer + length; the copy is fine even though the Vec drops
        // after this call. Returns a GBytes with ref-count 1.
        let bytes = unsafe { ffi::g_bytes_new(pixels.as_ptr().cast::<c_void>(), pixels.len()) };
        assert!(!bytes.is_null(), "g_bytes_new() returned NULL");
        // This code can drop the Vec now: g_bytes_new copied the bytes.
        drop(pixels);

        // SAFETY: display pointer is valid; `bytes` is a live GBytes; width,
        // height, stride are the values this code just validated against
        // `storage_len`. `wpe_buffer_shm_new` takes ownership of one reference
        // to `bytes` - but the current headers document it as a plain borrow.
        // This code keeps a reference and unref explicitly below to be safe on either
        // interpretation.
        let ptr = unsafe {
            ffi::wpe_buffer_shm_new(
                display.as_ptr(),
                width as _,
                height as _,
                ffi::WPEPixelFormat::Argb8888,
                bytes,
                stride,
            )
        };
        // SAFETY: unref the reference to the GBytes; the buffer holds its own.
        unsafe { ffi::g_bytes_unref(bytes) };

        assert!(
            !ptr.is_null(),
            "wpe_buffer_shm_new() returned NULL for {}x{} @ stride {} — the WPE \
             platform refused the buffer. This is a real WPE-side refusal, not \
             a mock fallback.",
            width,
            height,
            stride,
        );
        SharedBuffer {
            ptr,
            _pixels_owned_by_buffer: (),
        }
    }

    /// The buffer's declared pixel format, read back through the FFI.
    #[must_use]
    pub fn format(&self) -> ffi::WPEPixelFormat {
        // SAFETY: `self.ptr` is a live WPEBufferSHM.
        unsafe { ffi::wpe_buffer_shm_get_format(self.ptr) }
    }

    /// The buffer's width in pixels, read back through the base-class FFI.
    #[must_use]
    pub fn width(&self) -> u32 {
        // SAFETY: WPEBufferSHM is a WPEBuffer subclass, so upcasting the
        // pointer for `wpe_buffer_get_width` is safe (single-inheritance
        // GObject rules).
        let w = unsafe { ffi::wpe_buffer_get_width(self.ptr.cast::<ffi::WPEBuffer>()) };
        assert!(w > 0, "wpe_buffer_get_width returned non-positive {w}");
        w as u32
    }

    /// The buffer's height in pixels.
    #[must_use]
    pub fn height(&self) -> u32 {
        // SAFETY: as `width`.
        let h = unsafe { ffi::wpe_buffer_get_height(self.ptr.cast::<ffi::WPEBuffer>()) };
        assert!(h > 0, "wpe_buffer_get_height returned non-positive {h}");
        h as u32
    }

    /// The buffer's row stride in bytes.
    #[must_use]
    pub fn stride(&self) -> u32 {
        // SAFETY: `self.ptr` is a live WPEBufferSHM.
        unsafe { ffi::wpe_buffer_shm_get_stride(self.ptr) }
    }

    /// Read the pixels back through the FFI, into a fresh `Vec<u8>`.
    ///
    /// The returned bytes are in the buffer's native `ARGB8888` order (cairo
    /// convention: on little-endian, per-pixel memory is `B,G,R,A`) and may
    /// carry stride padding beyond `width * 4`. Consumers should route them
    /// through `copy_native_bgra_to_rgba`, which combines the shared RGBA
    /// preflight with de-padding and channel conversion in a single pass;
    /// [`argb8888_bytes_to_rgba8`] is the tight-buffer channel swap and is
    /// insufficient on its own when the native stride is padded.
    #[must_use]
    pub fn read_pixels(&self) -> Vec<u8> {
        // SAFETY: `self.ptr` is a live WPEBufferSHM; `wpe_buffer_shm_get_data`
        // returns a borrowed `GBytes*` per the GIR annotation
        // `transfer-ownership="none"` - the buffer owns the GBytes; this code must not
        // unref the returned pointer.
        let bytes = unsafe { ffi::wpe_buffer_shm_get_data(self.ptr) };
        assert!(!bytes.is_null(), "wpe_buffer_shm_get_data() returned NULL");
        // SAFETY: `bytes` is live for the duration of `self` (the buffer owns
        // it). `g_bytes_get_data` returns a borrowed pointer valid as long as
        // `bytes` is alive; this code copies the payload out before this method returns.
        let mut size: usize = 0;
        let data = unsafe { ffi::g_bytes_get_data(bytes, &mut size as *mut usize) };
        // SAFETY: for a nonempty GBytes payload, `data` points at `size`
        // initialized bytes owned by `bytes`, which is owned by `self`. GLib
        // may validly return NULL for an empty payload; the helper handles that
        // before inspecting or copying the pointer.
        let (_, storage_len) = preflight_rgba8_storage(
            self.width(),
            self.height(),
            u64::from(self.stride()),
            &DecodeLimits::DEFAULT,
        )
        .expect("WPE shared-buffer full storage must pass RGBA preflight before readback copy");
        assert_eq!(
            size, storage_len,
            "WPE shared-buffer readback requires exactly `height * stride` bytes"
        );
        let out = unsafe { shared_buffer_payload(data, size) };
        // no `g_bytes_unref(bytes)` - borrowed pointer, not owned here.
        out
    }
}

impl Drop for SharedBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was produced by `wpe_buffer_shm_new` and held
        // with ref-count >= 1 throughout `self`'s lifetime. The buffer holds
        // the sole reference to its inner GBytes, released with the buffer.
        unsafe { ffi::g_object_unref(self.ptr.cast::<c_void>()) }
    }
}

/// Convert tightly packed little-endian cairo ARGB8888 bytes to RGBA.
///
/// # Panics
/// Panics if the byte count is not a whole number of four-byte pixels.
#[must_use]
pub fn argb8888_bytes_to_rgba8(argb: &[u8]) -> Vec<u8> {
    assert!(
        argb.len().is_multiple_of(4),
        "argb8888_bytes_to_rgba8 requires a length divisible by 4, got {}",
        argb.len()
    );
    argb.as_chunks::<4>()
        .0
        .iter()
        .map(bgra_pixel)
        .collect::<Vec<_>>()
        .into_flattened()
}

fn bgra_pixel(bgra: &[u8; 4]) -> [u8; 4] {
    [bgra[2], bgra[1], bgra[0], bgra[3]]
}

/// A native snapshot announcement that could not be trusted to index a
/// borrowed pixel buffer.
///
/// WebKit/WPE emit width, height, stride and byte count as native output.
/// A malformed set - non-positive dimensions, a stride narrower than four
/// bytes per pixel, or fewer bytes than the announced rows - would let a
/// row-by-row copy in the snapshot paths index out of bounds. These are
/// native-*output* failures, not internal invariants of this crate, so both
/// snapshot paths degrade them to a typed error
/// ([`SnapshotError::Failed`]/[`SessionError::SnapshotFailed`]) instead of
/// aborting the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeSnapshotError {
    /// The native output reported a non-positive width or height.
    NonPositiveDimensions { width: c_int, height: c_int },
    /// The shared RGBA geometry preflight refused the announcement (stride,
    /// byte length, pixel count, or decoded-byte limit).
    Geometry(RgbaGeometryError),
}

/// Validate the geometry a native snapshot reported before it is trusted to
/// index the pixel buffer, returning the shared
/// [`RgbaGeometry`](crate::frame::RgbaGeometry) layout on success.
///
/// Routes non-positive dimensions to a dedicated variant and every other
/// geometry refusal - stride vs width, byte length vs the last readable pixel
/// at `(height - 1) * stride + width * 4`, decoded-byte limits - through the
/// shared [`preflight_rgba8`] check so the snapshot paths share exactly the
/// ordering GStreamer uses.
///
/// Kept as a pure function so the mapping is testable at the seam without a
/// live renderer: a test feeds it malformed tuples and asserts the typed error,
/// with a well-formed tuple as the positive control.
pub(crate) fn validate_native_snapshot(
    width: c_int,
    height: c_int,
    stride: c_uint,
    byte_len: usize,
) -> Result<RgbaGeometry, NativeSnapshotError> {
    if width <= 0 || height <= 0 {
        return Err(NativeSnapshotError::NonPositiveDimensions { width, height });
    }
    preflight_rgba8(
        width as u32,
        height as u32,
        u64::from(stride),
        &DecodeLimits::DEFAULT,
    )
    .and_then(|layout| layout.check_byte_len(byte_len))
    .map_err(NativeSnapshotError::Geometry)
}

// Geometry is refused before allocating output. Tight planes are converted
// together; padded rows share one output allocation with no BGRA intermediate.
fn copy_native_bgra_to_rgba(
    width: c_int,
    height: c_int,
    stride: c_uint,
    bytes: &[u8],
) -> Result<Vec<u8>, NativeSnapshotError> {
    let layout = validate_native_snapshot(width, height, stride, bytes.len())?;
    if layout.stride() == layout.row_bytes() {
        return Ok(bytes[..layout.tight_len()]
            .as_chunks::<4>()
            .0
            .iter()
            .map(bgra_pixel)
            .collect::<Vec<_>>()
            .into_flattened());
    }
    let mut pixels = Vec::with_capacity(layout.tight_len() / 4);
    for row in 0..height as usize {
        let off = row * layout.stride();
        pixels.extend(
            bytes[off..off + layout.row_bytes()]
                .as_chunks::<4>()
                .0
                .iter()
                .map(bgra_pixel),
        );
    }
    Ok(pixels.into_flattened())
}

/// Round-trip a known-pattern buffer through WPE and return a validated
/// [`Rgba8Frame`].
///
/// The pattern is generated by `fill` (called with `(x, y)` for each pixel and
/// returning `(r, g, b, a)`). It is written into a `WPEBufferSHM` via the FFI,
/// read back through `wpe_buffer_shm_get_data`, converted from cairo byte order
/// to RGBA, and constructed as a validated `Rgba8Frame`. The returned frame
/// is a real round trip through WPE-owned memory, not a Vec filled and
/// returned.
///
/// # Panics
///
/// Every failure mode is a panic - feature `wpe` is on, caller wanted the real
/// path, silent substitution is forbidden. See the module docs.
#[must_use]
pub fn wpe_roundtrip_frame(
    display: &HeadlessDisplay,
    width: u32,
    height: u32,
    generation: Generation,
    seq: FrameSeq,
    fill: impl Fn(u32, u32) -> (u8, u8, u8, u8),
) -> Rgba8Frame {
    let stride_u64 = u64::from(width) * 4;
    preflight_rgba8(width, height, stride_u64, &DecodeLimits::DEFAULT)
        .expect("WPE round-trip geometry must pass before fixture allocation");
    let stride = u32::try_from(stride_u64).expect("accepted RGBA row fits WPE stride");
    let storage_len = u64::from(height)
        .checked_mul(stride_u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .expect("WPE round-trip full storage length fits usize");
    let mut bgra = Vec::with_capacity(storage_len);
    for y in 0..height {
        for x in 0..width {
            let (r, g, b, a) = fill(x, y);
            // Cairo ARGB32 on little-endian: memory bytes are B,G,R,A.
            bgra.extend_from_slice(&[b, g, r, a]);
        }
    }
    let buf = SharedBuffer::new_argb8888(display, width, height, stride, bgra);

    // Read the geometry BACK through the FFI so an off-by-one in the WPE side
    // shows up here rather than being trusted from what passed in.
    let (w, h, s) = (buf.width(), buf.height(), buf.stride());
    assert_eq!(w, width, "WPE reported width {w}, expected {width}");
    assert_eq!(h, height, "WPE reported height {h}, expected {height}");
    assert_eq!(s, stride, "WPE reported stride {s}, expected {stride}");
    assert_eq!(
        buf.format(),
        ffi::WPEPixelFormat::Argb8888,
        "WPE reported unexpected pixel format"
    );

    let argb = buf.read_pixels();
    assert_eq!(
        argb.len(),
        storage_len,
        "WPE returned {} pixel bytes, expected {}",
        argb.len(),
        storage_len,
    );
    let rgba = copy_native_bgra_to_rgba(w as c_int, h as c_int, s, &argb)
        .expect("WPE round-trip output passes native preflight");
    Rgba8Frame::new(generation, seq, width, height, rgba)
        .expect("a WPE-round-tripped frame at declared width/height is valid RGBA8")
}

// ===========================================================================
// WebView + snapshot: load a data:text/html page and render its pixels.
//
// # Termination guarantees - read this first
//
// A `GMainLoop` that never quits will hold the cargo lock and stall every
// other worker on this host. This module guarantees termination through THREE
// independent mechanisms:
//
// 1. Test-level `with_hard_deadline` wraps every call and panics the outer
//    thread if `snapshot_data_url` does not return in the given wall-clock
//    time. This is the last-resort net.
//
// 2. `g_timeout_add(deadline_ms, ...)` installs a GLib source that fires
//    unconditionally after `deadline_ms` milliseconds and calls
//    `g_main_loop_quit`. It runs regardless of whether the snapshot callback
//    ever fires. If the load hangs, the timeout wins.
//
// 3. `g_main_loop_quit` is idempotent (GLib guarantees this) - the
//    snapshot callback and the deadline callback both call it; whichever
//    fires first ends the loop, and the second is a documented no-op.
//
// If the loop returns without a frame (deadline first, or snapshot returned
// NULL), `snapshot_data_url` returns `Err(SnapshotError::Timeout | Failed)`.
// The test panics loudly on that Err - no silent mock substitution.
// ===========================================================================

/// Convert a caller-supplied URL into a C string, rejecting an interior
/// NUL byte as a typed error.
///
/// # Why this exists instead of `CString::new(url).expect(...)`
///
/// A URL reaching this layer is application input - typed into an address bar,
/// read from a config file, or built from a redirect. `CString::new` fails on an
/// interior NUL, and `expect` turned that into a process abort: one hostile
/// or malformed string took down the whole application, including every other
/// view sharing the engine. A URL that cannot be represented is an ordinary
/// rejection, not an invariant violation, so it is now a typed error.
///
/// # The diagnostic deliberately does not echo the URL
///
/// It reports the NUL's byte offset and the string's length instead. A URL can
/// be a multi-megabyte `data:` payload or carry credentials; copying it into an
/// error message would put both in logs. Offset plus length is what actually
/// identifies the defect.
///
/// # Callers validate BEFORE allocating
///
/// Every call site invokes this at the very top of its function, before a
/// `GMainLoop`, a `g_timeout_add` deadline, a connected signal handler or a raw
/// state box exists. The two `expect`s this replaced sat *after* all four, so a
/// naive in-place `?` would return with a deadline source still armed while the
/// guards free the box it points at.
///
/// Honest scope of that claim: the liveness of those resources at the old
/// position is a fact you can read off the code, but it is *not* something the
/// gates demonstrate. The in-place variant was tried as a sabotage
/// (`wpe_url_nul` sabotage 5) and passed: the stale 5 s timeout never gets
/// a chance to fire before the run ends, so the fault is latent and
/// timing-dependent rather than reproducible. Validating first is kept because
/// it removes the question entirely, not because a red test forced it.
fn url_to_cstring(url: &str) -> Result<CString, String> {
    CString::new(url).map_err(|e| {
        format!(
            "interior NUL at byte {} of a {}-byte URL; a URL may not contain a \
             NUL byte",
            e.nul_position(),
            url.len()
        )
    })
}

/// Convert WebKit's borrowed `current_uri` pointer into a bounded owned URI.
///
/// This is the read half of [`WebSession::current_uri`], factored out so the
/// null/over-limit/non-UTF-8 contract can be exercised with synthetic pointers
/// instead of requiring a live renderer to first navigate to a hostile URI.
///
/// A null pointer (WebKit reports no URI before the first load) stays
/// `Ok(None)`. A non-null URI is read through the one shared bounded scanner
/// ([`crate::ffi::policy::scan_bounded_native_uri`]) at the policy-URI byte
/// ceiling, so a page-controlled URI over
/// [`MAX_POLICY_URI_BYTES`](crate::ffi::policy::MAX_POLICY_URI_BYTES) is refused
/// with a typed error before it becomes a Rust allocation rather than being
/// silently truncated.
///
/// # Safety
///
/// `uri` must be null or point to a readable NUL-terminated C string that
/// remains live for this call.
unsafe fn current_uri_from_native(
    uri: *const c_char,
) -> Result<Option<String>, crate::ffi::policy::NativeUriError> {
    if uri.is_null() {
        // A null URI is the absence of a load, not a refusal: it must stay
        // `None`, distinct from the shared scanner's typed `Null` error.
        return Ok(None);
    }
    // SAFETY: the caller contract is forwarded unchanged; the shared scanner
    // bounds the read to the policy-URI byte ceiling before allocating.
    unsafe {
        crate::ffi::policy::scan_bounded_native_uri(uri, crate::ffi::policy::MAX_POLICY_URI_BYTES)
    }
    .map(Some)
}

/// Why a `snapshot_data_url` call did not produce a frame.
///
/// # Compatibility
///
/// `#[non_exhaustive]`. Sandbox enforcement adds failure modes over time, and a
/// security check must never be omitted because adding its variant would be a
/// breaking change. Downstream code must carry a wildcard arm and treat an
/// unrecognised variant as a failure - which is the safe direction, since every
/// variant of this enum means "no frame was produced".
#[derive(Debug)]
#[non_exhaustive]
pub enum SnapshotError {
    /// The caller-supplied URL contained an interior NUL byte and could not be
    /// passed to WebKit. Rejected before any resource is allocated - this used
    /// to abort the process.
    InvalidUrl(String),
    /// The standalone snapshot API accepts only a host-supplied `data:` URL.
    NonDataUrl,
    /// Its isolated ephemeral network session or mandatory guard failed.
    DestinationGuardUnavailable(String),
    /// The deadline `g_timeout_add` source fired before the snapshot callback.
    /// The load either did not finish or the snapshot never completed.
    Timeout,
    /// The snapshot callback fired but `webkit_web_view_get_snapshot_finish`
    /// returned NULL. Carries the glib error message if one was populated.
    Failed(String),
    /// `g_object_new_with_properties` returned NULL - that could not construct
    /// the `WebKitWebView`. Signals a WPE/WebKit build mismatch.
    WebViewConstructionFailed,
    /// The environment would weaken or skip WebProcess sandboxing, so no
    /// WebView was constructed and no renderer was spawned.
    SandboxDisabled(crate::sandbox::SandboxRefusal),
    /// A renderer could not be attested as isolated, so the snapshot was
    /// abandoned and the renderer terminated.
    SandboxNotAttested(crate::sandbox::UnattestedReason),
    /// A native WebKit signal returned handler id 0 (unknown/renamed signal),
    /// so the policy binding was refused and no view was exposed.
    /// Carries the exact signal name that could not be connected.
    NativeSignalBindFailed(&'static str),
}

/// Shared state passed to every GLib callback for one `snapshot_data_url`
/// call. Boxed and handed to the FFI as `*mut c_void`; recovered on the far
/// side of `g_main_loop_run` to free the box safely.
///
/// Ordering constraint: `main_loop` must not be null while any callback can
/// fire. This code installs callbacks only after the loop is created and stop the
/// loop before dropping the box.
#[repr(C)]
struct CallbackState {
    /// The `GMainLoop*` to quit. Any callback may quit it; quit is idempotent.
    main_loop: *mut ffi::GMainLoop,
    /// The `WebKitWebView*` - needed by the snapshot callback to call
    /// `get_snapshot_finish`.
    web_view: *mut ffi::WebKitWebView,
    /// Keeps the strict network session and its destination guard alive if a
    /// timed-out callback takes ownership of this state.
    _network_session: Option<Rc<crate::ffi::profile::NetworkSession>>,
    /// The `GCancellable*` passed to the async snapshot, so a timeout can cancel
    /// the outstanding call and the callback can never fire against this freed
    /// box. Owned here; unref'd on return.
    cancellable: *mut c_void,
    /// The `WebKitImage*` from the snapshot, or NULL if not yet obtained.
    /// Populated by the snapshot callback; owned (ref-count 1) if non-NULL.
    /// Read once after `g_main_loop_run` returns.
    result_image: *mut ffi::WebKitImage,
    /// The glib error message from a failed snapshot, if any.
    /// Owned `CString`; populated by the snapshot callback on error.
    error_message: *mut c_char,
    /// TRUE once `WEBKIT_LOAD_FINISHED` was seen - used by the load-changed
    /// callback to decide whether to fire the snapshot.
    load_finished: bool,
    /// TRUE once `webkit_web_view_get_snapshot` has been kicked off.
    /// Guards against calling it twice from repeated `load-changed` signals.
    snapshot_started: bool,
    /// TRUE once `on_deadline` fired (auto-removing its source). If still false
    /// after the loop quits, the snapshot finished first and the deadline
    /// source must be removed so it cannot fire later against this freed box.
    deadline_fired: bool,
    /// TRUE once the async snapshot callback resolved (success, error, OR
    /// cancellation). If false after a timeout while a snapshot was started,
    /// the callback is still pending; the caller cancels and drains until this
    /// flips before freeing.
    callback_fired: bool,
    /// TRUE when the main thread's bounded drain expired and it transferred
    /// ownership of the box and every GLib object the callback can reach
    /// (`web_view`, `main_loop`, `cancellable`, `result_image`, `error_message`)
    /// to [`on_snapshot_ready`], which frees them when it finally fires. `false`
    /// on every normal path, where the main thread frees.
    abandoned: bool,
    /// Deterministic lifetime witness for `web_view`: set to the view pointer on
    /// the cap-expiry transfer path and registered with
    /// `g_object_add_weak_pointer`, so GLib NULLs it if the object is finalized
    /// before the abandoned callback runs. The callback checks it, turning a
    /// broken ownership transfer into an observable
    /// [`standalone_snapshot_lifetime_violation_count`] rather than a
    /// probabilistic use-after-free. NULL on every normal path.
    web_view_witness: std::cell::Cell<*mut c_void>,
    /// The same witness for `cancellable`.
    cancellable_witness: std::cell::Cell<*mut c_void>,
}

/// How long [`snapshot_data_url`] drains a cancelled snapshot callback before
/// handing it ownership of the state box and every GLib object it can reach.
/// Production default; the injectable seam is
/// [`snapshot_data_url_with_drain_cap`].
const SNAPSHOT_DATA_URL_DRAIN_CAP_MS: u64 = 2_000;

/// Deterministic mechanism counters for the native session path.
///
/// They count successful native work on the current WPE/main-context thread.
/// Use [`reset_native_runtime_counters`] to isolate an operation's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeRuntimeCounters {
    /// Blocking page loads started, including the constructor's inert bootstrap.
    pub loads_started: u64,
    /// Blocking page loads that reached `WEBKIT_LOAD_FINISHED`.
    pub loads_completed: u64,
    /// Persistent-session snapshots requested.
    pub snapshots_started: u64,
    /// Persistent-session snapshots converted into a valid `Rgba8Frame`.
    pub snapshots_completed: u64,
    /// Generation-accepted input events dispatched to WPE.
    pub inputs_dispatched: u64,
    /// Full-frame CPU copy passes used to extract session snapshots.
    pub frame_copy_passes: u64,
    /// Bytes written by those full-frame copy passes.
    pub frame_copy_bytes: u64,
    /// Liveness reads through an identity-bound process status descriptor.
    pub liveness_descriptor_checks: u64,
    /// Liveness reads through a fresh process status path lookup.
    pub liveness_fallback_checks: u64,
}

thread_local! {
    static NATIVE_RUNTIME_COUNTERS: std::cell::Cell<NativeRuntimeCounters> =
        const { std::cell::Cell::new(NativeRuntimeCounters {
            loads_started: 0,
            loads_completed: 0,
            snapshots_started: 0,
            snapshots_completed: 0,
            inputs_dispatched: 0,
            frame_copy_passes: 0,
            frame_copy_bytes: 0,
            liveness_descriptor_checks: 0,
            liveness_fallback_checks: 0,
        }) };

    /// How many times a cancelled snapshot callback completed its own
    /// abandoned-path cleanup on this thread. A gate reads it
    /// before and after pumping to prove the callback ran and released, rather
    /// than that the process merely survived - mirroring
    /// [`crate::ffi::a11y::abandoned_cleanup_count`].
    ///
    /// This counts `WebSession::snapshot` abandoned cleanups only; the
    /// standalone [`snapshot_data_url`] path has its own distinct counter,
    /// [`STANDALONE_SNAPSHOT_ABANDONED_CLEANUPS`], so a gate for one
    /// path cannot be satisfied by the other's cleanup.
    static SNAPSHOT_ABANDONED_CLEANUPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// How many times a cancelled standalone [`snapshot_data_url`] callback
    /// completed its own abandoned-path cleanup on this thread. Distinct
    /// from the session-snapshot counter above.
    static STANDALONE_SNAPSHOT_ABANDONED_CLEANUPS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    /// How many times an abandoned standalone-snapshot callback found a resource
    /// it was handed already finalized (its weak witness NULL). Must stay 0:
    /// any increment means a main-thread guard freed a callback-reachable
    /// pointee, i.e. the ownership transfer is broken.
    static STANDALONE_SNAPSHOT_LIFETIME_VIOLATIONS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// Reset the current thread's native-session mechanism counters.
pub fn reset_native_runtime_counters() {
    NATIVE_RUNTIME_COUNTERS.set(NativeRuntimeCounters::default());
}

/// Read the current thread's native-session mechanism counters.
#[must_use]
pub fn native_runtime_counters() -> NativeRuntimeCounters {
    NATIVE_RUNTIME_COUNTERS.get()
}

pub(super) fn record_native_load(started: bool) {
    NATIVE_RUNTIME_COUNTERS.set(NATIVE_RUNTIME_COUNTERS.get().record_load(started));
}

pub(super) fn record_native_liveness(descriptor: bool) {
    let mut counters = NATIVE_RUNTIME_COUNTERS.get();
    if descriptor {
        counters.liveness_descriptor_checks += 1;
    } else {
        counters.liveness_fallback_checks += 1;
    }
    NATIVE_RUNTIME_COUNTERS.set(counters);
}

pub(super) fn record_native_snapshot(started: bool) {
    NATIVE_RUNTIME_COUNTERS.set(NATIVE_RUNTIME_COUNTERS.get().record_snapshot(started));
}

pub(super) fn record_native_input() {
    let mut counters = NATIVE_RUNTIME_COUNTERS.get();
    counters.inputs_dispatched += 1;
    NATIVE_RUNTIME_COUNTERS.set(counters);
}

pub(super) fn record_native_frame_copy(bytes: usize) {
    let mut counters = NATIVE_RUNTIME_COUNTERS.get();
    counters.frame_copy_passes += 1;
    counters.frame_copy_bytes += bytes as u64;
    NATIVE_RUNTIME_COUNTERS.set(counters);
}

impl NativeRuntimeCounters {
    fn record_load(mut self, started: bool) -> Self {
        if started {
            self.loads_started += 1;
        } else {
            self.loads_completed += 1;
        }
        self
    }

    fn record_snapshot(mut self, started: bool) -> Self {
        if started {
            self.snapshots_started += 1;
        } else {
            self.snapshots_completed += 1;
        }
        self
    }
}

/// How many times a cancelled snapshot callback completed its own
/// abandoned-path cleanup on this thread. Counts the
/// `WebSession::snapshot` path only; see
/// [`standalone_snapshot_abandoned_cleanup_count`] for the standalone path.
#[must_use]
pub fn snapshot_abandoned_cleanup_count() -> u64 {
    SNAPSHOT_ABANDONED_CLEANUPS.with(std::cell::Cell::get)
}

/// How many times a cancelled standalone [`snapshot_data_url`] callback
/// completed its own abandoned-path cleanup on this thread. Distinct
/// from [`snapshot_abandoned_cleanup_count`], which counts the session path.
#[must_use]
pub fn standalone_snapshot_abandoned_cleanup_count() -> u64 {
    STANDALONE_SNAPSHOT_ABANDONED_CLEANUPS.with(std::cell::Cell::get)
}

/// How many times an abandoned standalone-snapshot callback observed a resource
/// it owns as already finalized. A non-zero value is a proven lifetime
/// bug: a main-thread guard freed something the pending callback still reaches.
#[must_use]
pub fn standalone_snapshot_lifetime_violation_count() -> u64 {
    STANDALONE_SNAPSHOT_LIFETIME_VIOLATIONS.with(std::cell::Cell::get)
}

/// Free everything an abandoned [`CallbackState`] owns - the snapshot image, the
/// error string, the WebView, the main loop, the cancellable - then the box,
/// and record the cleanup. Called only by [`on_snapshot_ready`] on the
/// abandoned path.
///
/// Each GObject is checked against its weak witness first: a NULLed witness
/// means the pointee was finalized before this callback ran, so unref'ing it
/// would be the very use-after-free the transfer prevents. That case is
/// recorded, loudly, rather than performed.
///
/// # Safety
///
/// `ptr` must be the live, abandoned `CallbackState` box, run on the owning
/// (single) thread with no other reference outstanding.
unsafe fn free_abandoned_snapshot(ptr: *mut CallbackState) {
    // SAFETY: `ptr` came from `Box::into_raw`; every GLib object it names was
    // kept alive (the main thread forgot its guards) precisely for this moment.
    // `Box::from_raw` does not move the allocation, so the witness addresses
    // registered with GLib stay valid until the box drops below.
    let boxed = unsafe { Box::from_raw(ptr) };
    let mut violations = 0_u64;

    unsafe {
        // Callback-produced resources: the callback owns these outright, no
        // witness needed (they never existed on the main thread).
        if !boxed.result_image.is_null() {
            ffi::g_object_unref(boxed.result_image.cast::<c_void>());
        }
        if !boxed.error_message.is_null() {
            let _ = CString::from_raw(boxed.error_message);
        }
    }

    // GObjects transferred from the main thread: each was registered with a weak
    // witness at the transfer point. A NULLed witness proves a guard freed it.
    for (object, witness) in [
        (boxed.web_view.cast::<c_void>(), &boxed.web_view_witness),
        (boxed.cancellable, &boxed.cancellable_witness),
    ] {
        if object.is_null() {
            continue;
        }
        if witness.get().is_null() {
            // GLib nullified the witness: this object was finalized while the
            // callback was still outstanding. Do not unref a freed pointee.
            violations += 1;
            continue;
        }
        // SAFETY: the witness still names a live object registered here, so
        // removing the weak pointer and dropping the ref are both valid.
        unsafe {
            ffi::g_object_remove_weak_pointer(object, witness.as_ptr());
            ffi::g_object_unref(object);
        }
    }

    // The main loop is a boxed type, not a GObject, so it carries no weak
    // witness; the main thread deliberately did not unref it.
    // SAFETY: the loop, kept alive for this moment.
    unsafe { ffi::g_main_loop_unref(boxed.main_loop) };

    if violations > 0 {
        // Loud: a silently-recorded lifetime bug reads like a clean run.
        eprintln!(
            "enzui web-engine: STANDALONE SNAPSHOT LIFETIME VIOLATION — {violations} \
             resource(s) an abandoned snapshot_data_url callback owns were already \
             finalized; the cap-expiry ownership transfer is broken"
        );
        STANDALONE_SNAPSHOT_LIFETIME_VIOLATIONS.with(|c| c.set(c.get() + violations));
    }
    STANDALONE_SNAPSHOT_ABANDONED_CLEANUPS.with(|c| c.set(c.get() + 1));
}

/// The `load-changed` signal callback. GObject signal signature is
/// `(WebKitWebView*, WebKitLoadEvent, gpointer)`.
///
/// On `WEBKIT_LOAD_FINISHED` this code starts the async snapshot exactly once.
extern "C" fn on_load_changed(
    web_view: *mut ffi::WebKitWebView,
    load_event: c_int,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the boxed `CallbackState` passed in
    // `g_signal_connect_data`; the box outlives all callback firings because
    // this code does not free it until after `g_main_loop_run` returns and no source
    // is active. Non-aliasing: this is the only thread the GMainLoop dispatches
    // on, so callbacks are serialized.
    let state = unsafe { &mut *(user_data as *mut CallbackState) };

    if load_event != ffi::WEBKIT_LOAD_FINISHED {
        return;
    }
    if state.snapshot_started {
        // A redirected load can fire FINISHED twice. Ignore.
        return;
    }
    state.load_finished = true;
    state.snapshot_started = true;

    // SAFETY: `web_view` is the same `WebKitWebView*` passed in; the
    // callback state holds a matching pointer. `get_snapshot` is
    // fire-and-forget; the callback `on_snapshot_ready` receives the state.
    unsafe {
        ffi::webkit_web_view_get_snapshot(
            web_view,
            ffi::WEBKIT_SNAPSHOT_REGION_VISIBLE,
            ffi::WEBKIT_SNAPSHOT_OPTIONS_NONE,
            state.cancellable, // cancellable, so a timeout can cancel + drain it
            on_snapshot_ready,
            user_data,
        );
    }
}

/// The `get_snapshot` async-ready callback. Signature is
/// `(GObject*, GAsyncResult*, gpointer)` - the first argument is the source
/// (the WebView) as a plain `GObject*`.
///
/// Calls `get_snapshot_finish` (owns the returned `WebKitImage*`), stores it
/// on the state, and quits the main loop. On error, captures the message and
/// quits too.
extern "C" fn on_snapshot_ready(
    _source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    user_data: *mut c_void,
) {
    // SAFETY: see `on_load_changed`.
    let state = unsafe { &mut *(user_data as *mut CallbackState) };
    // Record that the async op resolved (success, error, or cancellation) -
    // this is the flag the timeout drain waits on before freeing the box.
    state.callback_fired = true;

    let mut error: *mut ffi::GError = ptr::null_mut();
    // SAFETY: `state.web_view` is live for the duration of this callback;
    // `result` is provided by GLib and valid for the callback body only.
    // `webkit_web_view_get_snapshot_finish` returns a WebKitImage* with
    // transfer=full or NULL; on NULL, `error` is populated with transfer=full.
    let image =
        unsafe { ffi::webkit_web_view_get_snapshot_finish(state.web_view, result, &mut error) };

    if image.is_null() {
        if !error.is_null() {
            // SAFETY: on NULL return, `error.message` is a valid UTF-8 C string
            // owned by the GError this code now owns.
            let msg = unsafe { CStr::from_ptr((*error).message) };
            let owned = CString::new(msg.to_bytes()).unwrap_or_default();
            state.error_message = owned.into_raw();
            // SAFETY: `error` was transfer=full; free it.
            unsafe { ffi::g_error_free(error) };
        }
    } else {
        state.result_image = image;
    }

    // Idempotent - safe whether this code succeeded or failed.
    // SAFETY: `state.main_loop` is a valid `GMainLoop*` for the duration of
    // any callback.
    unsafe { ffi::g_main_loop_quit(state.main_loop) };

    // if the main thread already gave up waiting, it
    // transferred ownership. Free everything it deliberately did not (which it
    // would otherwise have left this code to UAF), and record it. After this the box
    // is gone, so nothing else may read `state`.
    if state.abandoned {
        // SAFETY: this code owns the abandoned box; single-threaded, no other reader.
        unsafe { free_abandoned_snapshot(user_data as *mut CallbackState) };
    }
}

/// The `g_timeout_add` deadline callback. Signature is
/// `gboolean (*)(gpointer)` - return FALSE to remove the source.
///
/// Always quits the loop (idempotent, so racing with the snapshot callback
/// is safe). Returning FALSE removes the source so it does not re-fire.
extern "C" fn on_deadline(user_data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: see `on_load_changed`.
    let state = unsafe { &mut *(user_data as *mut CallbackState) };
    // Mark that the deadline fired (its source auto-removes on G_FALSE), so the
    // caller does not try to remove an already-removed source.
    state.deadline_fired = true;
    // SAFETY: `state.main_loop` is a valid `GMainLoop*`.
    unsafe { ffi::g_main_loop_quit(state.main_loop) };
    ffi::G_FALSE
}

/// Load a `data:` (or any) URL into a fresh `WebKitWebView` bound to the
/// given headless display, wait for `WEBKIT_LOAD_FINISHED`, take one
/// snapshot, and return the pixels as an `Rgba8Frame`.
///
/// # Termination
///
/// Bounded by `deadline_ms`. The GLib timeout source calls
/// `g_main_loop_quit` regardless of load state; if it fires before the
/// snapshot callback, this code returns `Err(Timeout)`.
///
/// # Ownership
///
/// - `WebKitWebView` - constructed here, unref'd on return.
/// - `WebKitImage` from the snapshot - transfer=full, unref'd here after
///   reading its bytes.
/// - `GBytes` from `webkit_image_as_bytes` - transfer=none, not unref'd.
/// - `GMainLoop` - constructed here, unref'd on return.
///
/// # Errors
///
/// - `SnapshotError::Timeout` - the deadline fired first.
/// - `SnapshotError::Failed` - `get_snapshot_finish` returned NULL.
/// - `SnapshotError::WebViewConstructionFailed` - g_object_new returned NULL.
///
/// Never falls back to a mock frame on error - the test must observe the
/// real WebKit failure.
pub fn snapshot_data_url(
    display: &HeadlessDisplay,
    url: &str,
    deadline_ms: u32,
    generation: Generation,
    seq: FrameSeq,
) -> Result<Rgba8Frame, SnapshotError> {
    snapshot_data_url_with_drain_cap(
        display,
        url,
        deadline_ms,
        generation,
        seq,
        SNAPSHOT_DATA_URL_DRAIN_CAP_MS,
    )
}

/// How long [`WebSession::require_isolated_web_process`] waits for a stable
/// renderer identity after a load.
///
/// Only an absent renderer or a census candidate that vanished during
/// inspection is polled. Every verdict about a live renderer is immediate, and
/// budget expiry is a refusal.
pub const SANDBOX_ATTESTATION_BUDGET_MS: u64 = 3_000;

/// How long an enforcement path waits for a termination it requested to be
/// observable - both as WebKit's `web-process-terminated` signal and as the
/// renderer's disappearance from `/proc`.
pub const SANDBOX_TERMINATION_BUDGET_MS: u64 = 5_000;

/// The inert page every native view loads before any caller content.
///
/// `about:blank` has no script, no network fetch and no caller-controlled
/// bytes, so spawning a renderer on it cannot execute anything an attacker
/// chose. Attestation happens on this renderer; only then may a caller URI be
/// loaded.
pub const INERT_BOOTSTRAP_URL: &str = "about:blank";

/// How long the inert bootstrap load may take before the view is refused.
pub const BOOTSTRAP_DEADLINE_MS: u32 = 10_000;

/// Whether a URL names inert host-supplied content rather than a network
/// destination. Only the private bootstrap and `data:` URLs qualify.
#[must_use]
pub fn is_inert_url(url: &str) -> bool {
    url == INERT_BOOTSTRAP_URL || url.starts_with("data:")
}

/// [`snapshot_data_url`] without the sandbox preflight.
///
/// # This is not a production entry point
///
/// It is compiled only under the `sandbox-test-entrypoints` feature, which
/// nothing in the product enables, so a production build does not contain an
/// unpreflighted native render at all - a name alone is not a boundary. Its one
/// caller is the sandbox gate's negative control, which must start a real
/// WebKit renderer with the sandbox switched off in order to prove the
/// attestation reports it as not isolated.
///
/// It still runs the post-spawn half of the policy (inert bootstrap +
/// attestation), so what it skips is exactly the preflight and nothing else.
///
/// # Errors
///
/// As [`snapshot_data_url`].
#[cfg(feature = "sandbox-test-entrypoints")]
#[doc(hidden)]
pub fn snapshot_data_url_without_sandbox_preflight_for_negative_control(
    display: &HeadlessDisplay,
    url: &str,
    deadline_ms: u32,
    generation: Generation,
    seq: FrameSeq,
) -> Result<Rgba8Frame, SnapshotError> {
    snapshot_data_url_inner(
        display,
        url,
        deadline_ms,
        generation,
        seq,
        SNAPSHOT_DATA_URL_DRAIN_CAP_MS,
        crate::sandbox::OuterSandbox::Rejected,
        AttestBeforeContent::Skip,
    )
}

/// Whether a native path attests its renderer before caller content runs.
///
/// Only the negative control skips it, and only so the gate can observe an
/// unattested renderer instead of being refused before one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttestBeforeContent {
    /// Bootstrap inert content, attest, and refuse before the caller URL.
    Enforce,
    /// Skip the pre-content attestation (negative control only).
    #[cfg_attr(not(feature = "sandbox-test-entrypoints"), allow(dead_code))]
    Skip,
}

/// The navigation gate reachable from a native callback.
///
/// `WebSession::require_navigable` cannot be used from inside a GObject signal
/// handler - the session is borrowed by WebKit at that point - so the policy
/// layer's certificate retry calls this instead. It applies the same rule
/// against the same scoped baseline and the same outer-sandbox policy, and it
/// terminates a renderer it cannot attest rather than navigating it.
///
/// It deliberately does not re-bootstrap: a callback is not a place to
/// spawn a renderer. No attested renderer means the navigation is refused.
///
/// # Errors
///
/// The [`crate::sandbox::UnattestedReason`] the caller must refuse on.
pub(crate) fn enforce_navigation_on_view(
    web_view: *mut ffi::WebKitWebView,
    baseline: &[crate::sandbox::ProcessIdentity],
    outer: crate::sandbox::OuterSandbox,
) -> Result<(), crate::sandbox::UnattestedReason> {
    match attest_scoped(web_view, baseline, outer) {
        Ok(_) => Ok(()),
        Err(reason) => {
            let subject = attest_native_view(web_view, baseline, outer).subject();
            let _ =
                terminate_and_verify_view(web_view, None, subject, SANDBOX_TERMINATION_BUDGET_MS);
            Err(reason)
        }
    }
}

/// Attest this native view, using its renderer PID inside Flatpak.
///
/// Scoped rather than global: taking the worst renderer in the whole process
/// would let one view's verdict condemn another view's page, and would make a
/// caller terminate a renderer its `WebKitWebView` does not own.
fn attest_native_view(
    web_view: *mut ffi::WebKitWebView,
    baseline: &[crate::sandbox::ProcessIdentity],
    outer: crate::sandbox::OuterSandbox,
) -> crate::sandbox::SandboxAttestation {
    if outer == crate::sandbox::OuterSandbox::AcceptedByHost
        && crate::sandbox::detect_container_now() == Some(crate::sandbox::ContainerKind::Flatpak)
    {
        // SAFETY: callers retain this native view on its owner thread.
        return match unsafe { process_memory::renderer_pid_for_view(web_view) } {
            Ok(Some(pid)) => crate::sandbox::attest_flatpak_renderer(pid),
            Ok(None) => crate::sandbox::SandboxAttestation::Unattested(
                crate::sandbox::UnattestedReason::WebProcessNotFound,
            ),
            Err(_) => crate::sandbox::SandboxAttestation::Unattested(
                crate::sandbox::UnattestedReason::FlatpakIsolationFailed {
                    pid: None,
                    why: "native runtime cannot identify this view's renderer".into(),
                },
            ),
        };
    }
    crate::sandbox::attest_current_process_excluding(baseline)
}

fn attest_scoped(
    web_view: *mut ffi::WebKitWebView,
    baseline: &[crate::sandbox::ProcessIdentity],
    outer: crate::sandbox::OuterSandbox,
) -> Result<crate::sandbox::SandboxAttestation, crate::sandbox::UnattestedReason> {
    let verdict = attest_native_view(web_view, baseline, outer);
    crate::sandbox::enforcement_decision_with_outer(
        &verdict,
        outer,
        crate::sandbox::detect_container_now(),
    )
    .map(|()| verdict)
}

fn is_transient_attestation(verdict: &crate::sandbox::SandboxAttestation) -> bool {
    matches!(
        verdict,
        crate::sandbox::SandboxAttestation::Unattested(
            crate::sandbox::UnattestedReason::WebProcessNotFound
                | crate::sandbox::UnattestedReason::ProcessVanished { .. }
        )
    )
}

fn await_attestation_with<Attest, Wait>(
    mut attest: Attest,
    mut wait_for_retry: Wait,
) -> crate::sandbox::SandboxAttestation
where
    Attest: FnMut() -> crate::sandbox::SandboxAttestation,
    Wait: FnMut() -> bool,
{
    loop {
        let verdict = attest();
        if !is_transient_attestation(&verdict) || !wait_for_retry() {
            return verdict;
        }
    }
}

fn await_scoped_attestation(
    web_view: *mut ffi::WebKitWebView,
    outer: crate::sandbox::OuterSandbox,
    baseline: &[crate::sandbox::ProcessIdentity],
    budget_ms: u64,
) -> crate::sandbox::SandboxAttestation {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
    await_attestation_with(
        || attest_native_view(web_view, baseline, outer),
        || {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            // SAFETY: NULL selects the default context; FALSE makes this nonblocking.
            unsafe {
                let _ = ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_FALSE);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let delay = remaining.min(std::time::Duration::from_millis(25));
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            true
        },
    )
}

/// Ask WebKit to terminate `web_view`'s renderer and verify that it did.
///
/// Two independent observations, both required:
///
/// * the kernel no longer has the exact `subject` identity, and
/// * WebKit delivered `web-process-terminated` for this view.
///
/// The first is the fact; the second proves the termination was *this view's*.
/// A caller that reports "terminated" on the strength of the void API call
/// alone is asserting something it never observed - and if the offending
/// renderer belongs to another view, the call cannot reach it at all.
///
/// # Errors
///
/// A description of what could not be shown.
fn terminate_and_verify_view(
    web_view: *mut ffi::WebKitWebView,
    termination_state: Option<*mut TerminationState>,
    subject: Option<crate::sandbox::ProcessIdentity>,
    budget_ms: u64,
) -> Result<(), String> {
    // SAFETY: `web_view` is a live view owned by the caller for this call.
    unsafe { ffi::webkit_web_view_terminate_web_process(web_view) };
    await_termination(termination_state, subject, budget_ms)
}

/// Waits, within `budget_ms`, until both facts are observed: the renderer
/// identity has exited (gone from `/proc`, or a zombie its sandbox parent has
/// not reaped yet) and WebKit delivered `web-process-terminated`.
fn await_termination(
    termination_state: Option<*mut TerminationState>,
    subject: Option<crate::sandbox::ProcessIdentity>,
    budget_ms: u64,
) -> Result<(), String> {
    let Some(subject) = subject else {
        return Err(
            "no renderer identity was recorded, so no termination can be verified".to_string(),
        );
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
    loop {
        // Drive the main context so WebKit can deliver `web-process-terminated`.
        // SAFETY: NULL context = default; may_block=FALSE returns at once.
        unsafe {
            let _ = ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_FALSE);
        }
        let gone = crate::sandbox::process_is_gone(subject);
        let signalled = termination_state.is_none_or(|state| {
            // SAFETY: the box lives with the session and callbacks run on this
            // thread.
            unsafe { (*state).reason.get().is_some() }
        });
        if gone && signalled {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "after {budget_ms}ms: renderer pid {} still present = {}, \
                 web-process-terminated delivered = {signalled}",
                subject.pid, !gone
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// [`snapshot_data_url`] with an explicit drain cap, so the callback-owned
/// ownership-transfer branch can be reached deterministically.
///
/// This is the smallest test seam: the public [`snapshot_data_url`] signature
/// and its production cap (`SNAPSHOT_DATA_URL_DRAIN_CAP_MS`) are unchanged;
/// only tests pass a different cap.
///
/// A `drain_cap_ms` of `0` returns from the drain loop before it iterates the
/// context even once, so a snapshot whose deadline fired first cannot have
/// resolved its callback yet and the transfer branch runs on every invocation.
/// That is what lets a gate prove the abandoned callback afterwards frees the
/// box, the loop, the cancellable, the image/error and the WebView ref -
/// observed through [`standalone_snapshot_abandoned_cleanup_count`] and
/// [`standalone_snapshot_lifetime_violation_count`] - rather than that the
/// process merely survived. Mirrors
/// [`WebSession::snapshot_with_drain_cap`] and the profile
/// [`run_bounded`](crate::ffi::profile) drain cap.
///
/// # Errors
///
/// As [`snapshot_data_url`].
pub fn snapshot_data_url_with_drain_cap(
    display: &HeadlessDisplay,
    url: &str,
    deadline_ms: u32,
    generation: Generation,
    seq: FrameSeq,
    drain_cap_ms: u64,
) -> Result<Rgba8Frame, SnapshotError> {
    snapshot_data_url_with_policy(
        display,
        url,
        deadline_ms,
        generation,
        seq,
        drain_cap_ms,
        crate::ffi::deployment::sandbox_policy(),
    )
}

/// [`snapshot_data_url_with_drain_cap`] under an explicit outer-sandbox policy.
///
/// The policy reaches both halves of enforcement here, exactly as it does for
/// [`WebSession`]: [`crate::sandbox::OuterSandbox::AcceptedByHost`] would
/// otherwise be a claim with no production path to it.
///
/// # Errors
///
/// As [`snapshot_data_url`], plus
/// [`SnapshotError::SandboxNotAttested`] when the renderer this call spawned
/// cannot be shown to be isolated.
pub fn snapshot_data_url_with_policy(
    display: &HeadlessDisplay,
    url: &str,
    deadline_ms: u32,
    generation: Generation,
    seq: FrameSeq,
    drain_cap_ms: u64,
    outer: crate::sandbox::OuterSandbox,
) -> Result<Rgba8Frame, SnapshotError> {
    // This path builds a real WebKitWebView and spawns a WebProcess, so it
    // preflights the sandbox exactly like `WebSession`.
    //
    // Scope, stated rather than implied: this entry point gets the *preflight*
    // half of the policy only. `WebSession::load` can also enforce after the
    // spawn because it owns a live view it can terminate; this call constructs
    // a view, snapshots once and tears it down, so by the time a verdict could
    // be read the renderer may already be gone and "not found" would have to be
    // tolerated - which is precisely the fail-open the enforcement exists to
    // prevent. Long-lived rendering belongs on `WebSession`.
    crate::sandbox::preflight_in(&crate::sandbox::RealEnv, outer)
        .map_err(SnapshotError::SandboxDisabled)?;
    snapshot_data_url_inner(
        display,
        url,
        deadline_ms,
        generation,
        seq,
        drain_cap_ms,
        outer,
        AttestBeforeContent::Enforce,
    )
}

#[allow(clippy::too_many_arguments)]
fn snapshot_data_url_inner(
    display: &HeadlessDisplay,
    url: &str,
    deadline_ms: u32,
    generation: Generation,
    seq: FrameSeq,
    drain_cap_ms: u64,
    outer: crate::sandbox::OuterSandbox,
    attest: AttestBeforeContent,
) -> Result<Rgba8Frame, SnapshotError> {
    // Preserve the representation check first. Both checks run before any
    // WebKit allocation; this convenience capability accepts host data only.
    let url_c = url_to_cstring(url).map_err(SnapshotError::InvalidUrl)?;
    if !url.starts_with("data:") {
        return Err(SnapshotError::NonDataUrl);
    }

    // Record the renderers that already exist, so the verdict below is about
    // the renderer THIS call spawns and not about somebody else's.
    let sandbox_baseline = crate::sandbox::current_web_processes();

    // ---- Build a WebKitWebView bound to the display ----
    //
    // WPE 2.44+ exposes a construct-only "display" property on WebKitWebView;
    // using it means this code avoids libwpe-1.0's `wpe_view_backend`/
    // `WebKitWebViewBackend` machinery entirely.

    let display_ptr = display.as_ptr().cast::<c_void>();

    // SAFETY: both `_get_type` calls are pure GObject accessors that always
    // succeed once the shared library is loaded (which linking proved).
    let (view_gtype, display_gtype) =
        unsafe { (ffi::webkit_web_view_get_type(), ffi::wpe_display_get_type()) };

    let network_session = Rc::new(
        crate::ffi::profile::NetworkSession::new_ephemeral_with_policy(
            crate::web::DestinationPolicy::DEFAULT,
        )
        .map_err(|error| SnapshotError::DestinationGuardUnavailable(error.to_string()))?,
    );
    let display_name = CString::new("display").expect("static string, no NUL");
    let network_name = CString::new("network-session").expect("static string, no NUL");
    let names = [display_name.as_ptr(), network_name.as_ptr()];
    let mut values = [ffi::GValue::default(), ffi::GValue::default()];
    unsafe {
        ffi::g_value_init(&mut values[0], display_gtype);
        ffi::g_value_set_object(&mut values[0], display_ptr);
        ffi::g_value_init(&mut values[1], ffi::webkit_network_session_get_type());
        ffi::g_value_set_object(&mut values[1], network_session.as_ptr().cast::<c_void>());
    }

    let web_view = unsafe {
        ffi::g_object_new_with_properties(view_gtype, 2, names.as_ptr(), values.as_ptr())
    } as *mut ffi::WebKitWebView;

    for value in &mut values {
        unsafe { ffi::g_value_unset(value) };
    }

    if web_view.is_null() {
        return Err(SnapshotError::WebViewConstructionFailed);
    }

    // Guard so this code always unrefs the view.
    // The view's accessible gets the same bind recorder a `WebSession`
    // installs. Without it, a standalone view abandoned mid-load (a snapshot
    // deadline) crashed WebKit inside the AT-SPI bridge on the next load
    // once an assistive client activated it - which a desktop with the a11y
    // bus running does unprompted. `wpe_render_data_url` caught it; a session
    // view torn down the same way did not crash.
    // SAFETY: `web_view` is live; the WPEView and its accessible are borrowed
    // from it.
    let accessible = unsafe {
        let wpe_view = ffi::webkit_web_view_get_wpe_view(web_view);
        if wpe_view.is_null() {
            ptr::null_mut()
        } else {
            ffi::wpe_view_get_accessible(wpe_view)
        }
    };
    if !accessible.is_null() {
        // SAFETY: a live accessible, on the engine thread.
        unsafe { crate::ffi::a11y::install_bind_recorder(accessible) };
    }
    struct ViewGuard(*mut ffi::WebKitWebView, *mut ffi::WPEViewAccessible);
    impl Drop for ViewGuard {
        fn drop(&mut self) {
            if !self.1.is_null() {
                crate::ffi::a11y::forget_accessible(self.1);
            }
            // SAFETY: `self.0` is a `WebKitWebView*` owned here.
            unsafe { ffi::g_object_unref(self.0.cast::<c_void>()) };
        }
    }
    let _view_guard = ViewGuard(web_view, accessible);
    let actual_network = unsafe { ffi::webkit_web_view_get_network_session(web_view) };
    if actual_network != network_session.as_ptr() {
        return Err(SnapshotError::DestinationGuardUnavailable(
            "WebKit did not bind the isolated network session".into(),
        ));
    }
    let _proxy_authentication =
        ProxyAuthenticationBinding::install(web_view, network_session.as_ref())
            .map_err(SnapshotError::NativeSignalBindFailed)?;
    let native_policy = crate::ffi::policy::NativePolicyBinding::new(
        web_view,
        actual_network,
        crate::web::ViewId::new(u64::MAX - 1),
        crate::web::WebPolicy::strict(),
        outer,
        sandbox_baseline.clone(),
        |request| Some(request.id),
    )
    .map_err(|err| SnapshotError::NativeSignalBindFailed(err.signal))?;

    // ---- Spawn the renderer on INERT content and attest it BEFORE the
    // caller's URL is allowed to run ----
    //
    // Loading the caller's page first and attesting afterwards means the page's
    // scripts, subresource fetches and storage access have already happened in
    // whatever sandbox WebKit actually used. `about:blank` spawns the same
    // WebProcess with nothing attacker-chosen in it, so the verdict is read
    // before any caller content exists.
    if attest == AttestBeforeContent::Enforce {
        let bootstrap = CString::new(INERT_BOOTSTRAP_URL).expect("static, no NUL");
        native_policy.permit_inert_load(INERT_BOOTSTRAP_URL);
        let finished = run_load_on_view(web_view, &bootstrap, BOOTSTRAP_DEADLINE_MS).is_ok();
        let verdict = if finished {
            await_scoped_attestation(
                web_view,
                outer,
                &sandbox_baseline,
                SANDBOX_ATTESTATION_BUDGET_MS,
            )
        } else {
            attest_native_view(web_view, &sandbox_baseline, outer)
        };
        let subject = verdict.subject();
        let attested = if finished {
            crate::sandbox::enforcement_decision_with_outer(
                &verdict,
                outer,
                crate::sandbox::detect_container_now(),
            )
        } else {
            Err(crate::sandbox::UnattestedReason::WebProcessNotFound)
        };
        if let Err(reason) = attested {
            // A timed-out bootstrap may still have spawned a renderer; the
            // subject comes from the same census verdict being enforced.
            let _ =
                terminate_and_verify_view(web_view, None, subject, SANDBOX_TERMINATION_BUDGET_MS);
            return Err(SnapshotError::SandboxNotAttested(reason));
        }
    }

    // ---- Build the main loop and the callback state ----

    // SAFETY: `NULL` context means the default; ref-count 1.
    let main_loop = unsafe { ffi::g_main_loop_new(ptr::null_mut(), ffi::G_FALSE) };
    // INVARIANT, not an environmental failure: glib allocates through
    // `g_slice`/`g_malloc`, which abort the process internally on allocation
    // failure rather than returning NULL. A NULL here would mean the glib ABI
    // itself is broken, which no typed error could meaningfully recover, so
    // this stays an assertion.
    assert!(!main_loop.is_null(), "g_main_loop_new returned NULL");

    struct LoopGuard(*mut ffi::GMainLoop);
    impl Drop for LoopGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is the `GMainLoop*` owned here.
            unsafe { ffi::g_main_loop_unref(self.0) };
        }
    }
    let _loop_guard = LoopGuard(main_loop);

    // A cancellable for the async snapshot. On a timeout this code cancels it and drain
    // until the callback has fired, so it can never run against the freed box.
    // SAFETY: returns a GCancellable* rc=1.
    let cancellable = unsafe { ffi::g_cancellable_new() };
    // INVARIANT: as `g_main_loop_new` above - glib aborts on allocation failure,
    // so NULL is unreachable and stays an assertion rather than a typed error.
    assert!(!cancellable.is_null(), "g_cancellable_new returned NULL");
    struct CancelGuard(*mut c_void);
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            // SAFETY: the cancellable, rc=1.
            unsafe { ffi::g_object_unref(self.0) };
        }
    }
    let _cancel_guard = CancelGuard(cancellable);

    let state = Box::new(CallbackState {
        main_loop,
        web_view,
        _network_session: Some(network_session.clone()),
        cancellable,
        result_image: ptr::null_mut(),
        error_message: ptr::null_mut(),
        load_finished: false,
        snapshot_started: false,
        deadline_fired: false,
        callback_fired: false,
        abandoned: false,
        web_view_witness: std::cell::Cell::new(ptr::null_mut()),
        cancellable_witness: std::cell::Cell::new(ptr::null_mut()),
    });
    // Convert to raw pointer for FFI; recovered below.
    let state_ptr = Box::into_raw(state);

    // Guard to always recover and drop the box, even if this code panics below.
    struct StateGuard(*mut CallbackState);
    impl Drop for StateGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was produced by `Box::into_raw`; recover
                // ownership. Any owned resources it points at (image, error)
                // are freed by the outer function before this drop runs.
                let boxed = unsafe { Box::from_raw(self.0) };
                // Defensive cleanup in case an early return left resources
                // attached - freeing NULL is documented as a no-op.
                if !boxed.result_image.is_null() {
                    // SAFETY: transfer=full pointer this code holds.
                    unsafe { ffi::g_object_unref(boxed.result_image.cast::<c_void>()) };
                }
                if !boxed.error_message.is_null() {
                    // SAFETY: retake ownership of the CString leaked with
                    // `into_raw`.
                    let _ = unsafe { CString::from_raw(boxed.error_message) };
                }
            }
        }
    }
    let _state_guard = StateGuard(state_ptr);

    // ---- Install the deadline timeout FIRST, before any load starts ----
    //
    // This is deliberate: if `webkit_web_view_load_uri` were to synchronously
    // enter the main context (it does not, but as a defensive matter), the
    // deadline is already armed.

    // SAFETY: `on_deadline` has the `GSourceFunc` signature; `state_ptr` is
    // valid for the lifetime of the loop. Keep the id: if the snapshot finishes
    // first the deadline never fires, and it must be removed so it cannot fire
    // later against this box after it is freed. `WebSession::snapshot` enforces
    // the same callback-state lifetime invariant.
    let deadline_id =
        unsafe { ffi::g_timeout_add(deadline_ms, on_deadline, state_ptr.cast::<c_void>()) };

    // ---- Connect the load-changed signal ----
    //
    // g_signal_connect_data takes a GCallback (`void (*)(void)`). The real
    // callback has the concrete signal signature; cast via transmute - this
    // is the documented GObject pattern.

    // SAFETY: `on_load_changed` matches the concrete `load-changed` signal
    // signature `(WebKitWebView*, WebKitLoadEvent, gpointer)`. GObject casts
    // it back at the call site; this is the documented `GCallback` idiom.
    let callback: extern "C" fn() = unsafe {
        core::mem::transmute::<
            extern "C" fn(*mut ffi::WebKitWebView, c_int, *mut c_void),
            extern "C" fn(),
        >(on_load_changed)
    };
    // a zero handler id means `load-changed` was not connected, so the
    // snapshot would never fire and the loop would only ever quit on the
    // deadline. Refuse now: disarm the deadline source (so it cannot fire
    // against the box the StateGuard is about to free) and return a typed
    // error rather than blocking for the full deadline on a dead binding.
    // SAFETY: `web_view` is a valid GObject; `state_ptr` outlives the loop.
    let handler_id = match unsafe {
        crate::ffi::signal::connect_checked(
            web_view.cast::<c_void>(),
            "load-changed",
            callback,
            state_ptr.cast::<c_void>(),
        )
    } {
        Ok(id) => id,
        Err(err) => {
            // SAFETY: `deadline_id` is a live source created here and have not
            // removed; removing it before the box is freed prevents a
            // use-after-free by the timeout callback.
            unsafe { ffi::g_source_remove(deadline_id) };
            return Err(SnapshotError::NativeSignalBindFailed(err.signal));
        }
    };

    // ---- Kick off the load and run the loop ----

    // The exact data URL receives one private, single-use navigation permit.
    // Any network request it initiates is routed through the strict session.
    native_policy.permit_inert_load(url);
    // SAFETY: `web_view` is a valid WebView; `url_c` outlives the call.
    unsafe { ffi::webkit_web_view_load_uri(web_view, url_c.as_ptr()) };

    // SAFETY: `main_loop` is valid; blocks until `g_main_loop_quit` fires,
    // which is guaranteed by the deadline timeout even if the snapshot
    // callback never fires.
    unsafe { ffi::g_main_loop_run(main_loop) };

    // ---- The loop has returned. Disconnect and disarm before freeing. ----

    // Disconnect the load-changed handler so it cannot fire against the freed
    // box after this returns.
    // SAFETY: `handler_id` is the id returned above; disconnect is safe even if
    // the handler already ran.
    unsafe { g_signal_handler_disconnect(web_view.cast::<c_void>(), handler_id) };

    // If the deadline did not fire (the snapshot finished first), its source is
    // still registered pointing at `state`; remove it now, before the box is
    // freed.
    // SAFETY: single-threaded; `deadline_fired` written only by the (now-quit)
    // callback on this thread.
    if !unsafe { (*state_ptr).deadline_fired } {
        // SAFETY: a live source id created here and have not removed.
        unsafe { ffi::g_source_remove(deadline_id) };
    }

    // If the deadline fired while a snapshot was still outstanding, its callback
    // is pending and would fire later against this freed box. Cancel it and
    // drain the default context until the callback runs (it fires once, with
    // G_IO_ERROR_CANCELLED). Bounded so it cannot hang.
    // SAFETY: single-threaded reads of flags written only by (now-quit)
    // callbacks on this thread.
    if unsafe { (*state_ptr).snapshot_started } && !unsafe { (*state_ptr).callback_fired } {
        // SAFETY: the live cancellable.
        unsafe { ffi::g_cancellable_cancel(cancellable) };
        let drain_start = std::time::Instant::now();
        let drain_cap = std::time::Duration::from_millis(drain_cap_ms);
        loop {
            // SAFETY: single-threaded read of a flag written only by the
            // callback dispatched on this thread.
            if unsafe { (*state_ptr).callback_fired } {
                break;
            }
            if drain_start.elapsed() >= drain_cap {
                // cannot prove the cancelled callback ran within
                // the cap. Do not free anything it can still reach - the
                // per-scope guards below would free `web_view`/`main_loop`/
                // `cancellable`, and the late callback would then UAF, or
                // double-free the box. Instead TRANSFER ownership: mark the box
                // abandoned and forget the guards so they free nothing;
                // `on_snapshot_ready` frees image/error/web_view/main_loop/
                // cancellable/box when it finally fires and bumps
                // `STANDALONE_SNAPSHOT_ABANDONED_CLEANUPS`. This is
                // callback-owned cleanup completion, not a permanent leak.
                //
                // Register a weak witness on each GObject the callback inherits
                // (`web_view`, `cancellable`) BEFORE forgetting the guards, so a
                // broken transfer that frees a pointee shows up as a NULLed
                // witness - an observable
                // `standalone_snapshot_lifetime_violation_count` - rather than a
                // probabilistic UAF. The main loop is a boxed type, not
                // a GObject, so it carries no witness.
                // SAFETY: single-threaded; the callback has not run, so writing
                // the transfer fields races nothing. `web_view` and
                // `cancellable` are live GObjects this code may register witnesses on.
                unsafe {
                    let st = &*state_ptr;
                    st.web_view_witness.set(web_view.cast::<c_void>());
                    ffi::g_object_add_weak_pointer(
                        web_view.cast::<c_void>(),
                        st.web_view_witness.as_ptr(),
                    );
                    st.cancellable_witness.set(cancellable);
                    ffi::g_object_add_weak_pointer(cancellable, st.cancellable_witness.as_ptr());
                    (*state_ptr).abandoned = true;
                }
                core::mem::forget(_state_guard);
                core::mem::forget(_loop_guard);
                core::mem::forget(_view_guard);
                core::mem::forget(_cancel_guard);
                return Err(SnapshotError::Timeout);
            }
            // SAFETY: NULL context = default; may_block=FALSE returns at once,
            // so this loop is bounded by the wall-clock cap. This dispatches the
            // now-cancelled snapshot callback that flips `callback_fired`.
            unsafe {
                let _ = ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_FALSE);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    // ---- Inspect the state. No callback can fire now: the handler is
    // disconnected, the deadline source is gone, and any outstanding snapshot
    // callback has been drained above. ----

    // SAFETY: single-threaded read after the loop quit and all sources are
    // removed/drained.
    let state_ref = unsafe { &*state_ptr };

    if state_ref.result_image.is_null() {
        if !state_ref.error_message.is_null() {
            // SAFETY: CString this code owned via into_raw. Take a copy for the error.
            let msg = unsafe { CStr::from_ptr(state_ref.error_message) }
                .to_string_lossy()
                .into_owned();
            return Err(SnapshotError::Failed(msg));
        }
        return Err(SnapshotError::Timeout);
    }

    // ---- Extract the frame from the WebKitImage ----

    let image = state_ref.result_image;
    // SAFETY: `image` is a `WebKitImage*` with ref-count 1 (transfer=full).
    let width = unsafe { ffi::webkit_image_get_width(image) };
    let height = unsafe { ffi::webkit_image_get_height(image) };
    let stride = unsafe { ffi::webkit_image_get_stride(image) };

    // Native-output failures (a malformed snapshot from WebKit) degrade to a
    // typed error instead of aborting the process. Every early return
    // below leaves `state_ref.result_image` set, so the guards free the image,
    // the loop, the view and the cancellable on the way out - no leak.

    // SAFETY: `webkit_image_as_bytes` is transfer=none - borrowed. Valid as
    // long as `image` is alive (this code holds the ref).
    let bytes_ptr = unsafe { ffi::webkit_image_as_bytes(image) };
    if bytes_ptr.is_null() {
        return Err(SnapshotError::Failed(
            "webkit_image_as_bytes returned NULL for a non-NULL snapshot image".to_string(),
        ));
    }

    let mut size: usize = 0;
    // SAFETY: `bytes_ptr` is valid; `size` is written by glib.
    let data_ptr = unsafe { ffi::g_bytes_get_data(bytes_ptr, &mut size) };
    if data_ptr.is_null() {
        return Err(SnapshotError::Failed(
            "g_bytes_get_data returned NULL for a non-NULL snapshot buffer".to_string(),
        ));
    }

    // SAFETY: `data_ptr` points to `size` bytes owned by the GBytes and remains
    // live while `image` is held. The converter preflights geometry and length
    // before allocating or reading any row.
    let bgra_slice = unsafe { core::slice::from_raw_parts(data_ptr.cast::<u8>(), size) };
    let rgba = copy_native_bgra_to_rgba(width, height, stride, bgra_slice)
        .map_err(|error| SnapshotError::Failed(error.to_string()))?;

    // Now release the WebKitImage; its bytes are copied.
    // SAFETY: image was transfer=full; owned here. Guard would also free it
    // if this code returned early, but this code handles it here so the guard's cleanup is
    // a documented no-op on the now-NULL slot.
    unsafe { ffi::g_object_unref(image.cast::<c_void>()) };
    // Mark the state so the StateGuard does not double-free.
    // SAFETY: no callback can fire; single-threaded access.
    unsafe { (*state_ptr).result_image = ptr::null_mut() };

    Rgba8Frame::new(generation, seq, width as u32, height as u32, rgba)
        .map_err(|e| SnapshotError::Failed(format!("Rgba8Frame::new rejected: {e:?}")))
}

// ===========================================================================
// WebSession - a persistent WebView that can receive input.
//
// # Why a session, and not another `snapshot_data_url`
//
// `snapshot_data_url` builds a WebView, loads, snapshots once, and tears the
// whole thing down. Input forwarding needs the *same* WebView to survive
// across: load → snapshot(before) → dispatch(event) → pump → snapshot(after),
// so the after-snapshot observes a DOM change the dispatched event caused.
// A fresh view per step would lose the state the event mutated.
//
// # Termination uses three independent bounds
//
// Every blocking operation (`load`, `snapshot`) runs its own `GMainLoop`
// armed with a `g_timeout_add(deadline_ms, ...)` source installed BEFORE the
// operation starts. `g_main_loop_quit` is idempotent, so the completion
// callback and the deadline race harmlessly. `pump` does not run a nested
// loop at all - it iterates the context a bounded number of times with a hard
// wall-clock cap, so it cannot spin forever. And callers wrap the whole thing
// in `with_hard_deadline`, the outer net. The 1 ms deadline path is exercised
// on every test run.
// ===========================================================================

/// Maximum UTF-8 bytes copied from WebKit's borrowed page title.
///
/// Native pointer scanning stops at the first NUL (WebKit's C-string terminator)
/// or after this many bytes plus one, whichever comes first. A `document.title`
/// value the page controls therefore cannot force an unbounded native scan.
///
/// This budget is in native bytes, not scalars. Invalid native bytes decode
/// lossily through [`String::from_utf8_lossy`], and the U+FFFD replacement is
/// three UTF-8 bytes; the returned Rust string can be up to three times this
/// limit in bytes when every accepted native byte is replaced.
pub const MAX_PAGE_TITLE_BYTES: usize = 16 * 1024;

/// Revision of host-visible title, URI, cursor and load-failure state.
///
/// Compare only within one session. Revisions survive event-queue eviction and
/// consumption; IME and native focus must still be sampled independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageMetadataRevision {
    page: u64,
    cursor: u64,
    failures: u64,
}

/// Why [`WebSession::page_title`] refused a native title.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTitleError {
    /// No NUL terminator occurred within the accepted byte range.
    TooLong {
        /// Bytes observed before the scanner stopped without seeing a NUL.
        observed_bytes: usize,
        /// The maximum accepted title length in native bytes.
        max_bytes: usize,
    },
}

/// Convert WebKit's borrowed page-title pointer into a bounded owned string.
///
/// Factored out so the null / over-limit / lossy contract can be exercised with
/// synthetic pointers rather than a live renderer.
///
/// A null pointer (WebKit reports no title before a load names one) stays
/// `Ok(None)`. Non-null input is scanned to the first NUL through at most
/// [`MAX_PAGE_TITLE_BYTES`] plus one bytes and returned as an owned `String`
/// with invalid native bytes replaced through [`String::from_utf8_lossy`]. The
/// worst-case allocation is described on [`MAX_PAGE_TITLE_BYTES`].
///
/// # Safety
///
/// `title` must be null or point to a readable NUL-terminated C string that
/// remains live for this call.
pub(crate) unsafe fn page_title_from_native(
    title: *const c_char,
) -> Result<Option<String>, PageTitleError> {
    if title.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller guarantees a readable NUL-terminated string, and the
    // shared bounded scanner reads no more than the supplied bound + 1 bytes.
    let scanned =
        unsafe { crate::ffi::policy::scan_bounded_native_bytes(title, MAX_PAGE_TITLE_BYTES) };
    match scanned {
        Some(bytes) => Ok(Some(String::from_utf8_lossy(bytes).into_owned())),
        None => Err(PageTitleError::TooLong {
            observed_bytes: MAX_PAGE_TITLE_BYTES + 1,
            max_bytes: MAX_PAGE_TITLE_BYTES,
        }),
    }
}

/// Why a [`WebSession`] operation did not complete.
///
/// # Compatibility
///
/// `#[non_exhaustive]`, for the reason given on [`SnapshotError`]: enforcement
/// grows new refusal reasons, and every variant here is a failure, so a
/// downstream wildcard arm fails closed by construction.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionError {
    /// Another deferred renderer bootstrap still owns constructor admission.
    BootstrapBusy,
    /// Deferred renderer setup failed before publishing a usable session.
    BootstrapFailed(&'static str),
    /// The native display cannot apply the website color preference.
    ThemeSettingsUnavailable,
    /// The native display or view rejected a font preference.
    FontSettingsUnavailable,
    /// The native runtime lacks complete origin-scoped permission revocation support.
    OriginPermissionsUnsupported,
    /// The caller-supplied URL contained an interior NUL byte. Rejected before
    /// the load starts and before any GLib resource is allocated.
    InvalidUrl(String),
    /// Script input cannot be represented faithfully by the native API.
    InvalidScriptInput(crate::page::ScriptInputError),
    /// The isolated document-load readiness query failed.
    DocumentReadiness(crate::page::ScriptError),
    /// A host HTML document passed to
    /// [`WebSession::load_html`] exceeds [`MAX_HTML_DOCUMENT_BYTES`] or holds a
    /// NUL byte. Rejected before the load starts.
    InvalidDocument {
        /// The document's size in bytes.
        size: usize,
        /// The ceiling.
        limit: usize,
    },
    /// `g_object_new_with_properties(WEBKIT_TYPE_WEB_VIEW, ...)` returned NULL.
    WebViewConstructionFailed,
    /// `webkit_web_view_get_wpe_view` returned NULL - the WebKit view has no
    /// WPE platform backing, so input cannot be forwarded. A build mismatch,
    /// surfaced loudly rather than papered over with a mock.
    NoWpeView,
    /// [`set_gpu_process_for_webgl`] or [`set_gpu_process_for_compositing`]
    /// asked for the GPU process and the runtime lacks it.
    GpuProcessUnsupported,
    /// The WebProcess sandbox has been switched off in this environment, so a
    /// native session is refused before any WebKit resource is allocated;
    /// rendering is forbidden unless WebKit process sandboxing stays enabled.
    ///
    /// This is the fail-closed half of [`crate::sandbox`]: a page must never
    /// render in an unconfined WebProcess merely because a stray environment
    /// variable was exported.
    SandboxDisabled(crate::sandbox::SandboxRefusal),
    /// A renderer was spawned, but it could not be attested as reached through
    /// WebKit's bubblewrap launcher with its own mount/PID/user namespaces.
    /// The WebProcess is terminated before this is returned: a page
    /// that cannot be shown to be isolated is not shown at all.
    SandboxNotAttested(crate::sandbox::UnattestedReason),
    /// A renderer failed attestation and termination could not be verified
    /// within the budget.
    ///
    /// Distinct from [`SessionError::SandboxNotAttested`] on purpose: that one
    /// says "this code stopped it", this one says "this code asked and cannot show that it
    /// stopped". Reporting the second as the first would be a claim the process
    /// table does not support - for example when the offending renderer belongs
    /// to a different view, which `webkit_web_view_terminate_web_process`
    /// cannot reach.
    SandboxTerminationUnverified {
        /// Why the renderer was not attested in the first place.
        reason: crate::sandbox::UnattestedReason,
        /// What could not be shown about the termination.
        why: String,
    },
    /// A navigation was attempted on a session whose renderer is not (or is no
    /// longer) attested as isolated.
    ///
    /// Every navigation entry point funnels through the same check, so a page
    /// cannot be pointed at caller-supplied content by a route that forgot to
    /// enforce.
    SandboxNotEstablished(crate::sandbox::UnattestedReason),
    /// A blocking operation's deadline fired before it completed. Carries the
    /// operation name for a legible panic.
    Timeout(&'static str),
    /// A snapshot completed but `get_snapshot_finish` returned NULL.
    SnapshotFailed(String),
    /// A main-resource load failed. The bounded native domain/code omit URLs and error messages.
    LoadFailed { domain: String, code: i32 },
    /// WebKit reported a main-resource TLS failure during the blocking load.
    TlsLoadFailed,
    /// The app-owned profile could not be provisioned as a real network
    /// session. This is a loud refusal; the view is not created on WebKit's
    /// default profile as a fallback.
    Profile(crate::ffi::profile::ProfileError),
    /// GObject construction ignored or replaced the requested construct-only
    /// `network-session` property. Continuing would silently defeat profile
    /// isolation, so construction fails.
    ProfileNotBound,
    /// Crash recovery was requested for a low-level default-profile session;
    /// there is no app-owned profile identity to reconstruct safely.
    RecoveryRequiresProfile,
    /// Crash recovery was requested while the WebProcess is still live.
    RecoveryWhileLive,
    /// The supplied view id is no longer the router's live generation, so it
    /// cannot be the view whose process just terminated.
    RecoveryViewGone,
    /// Native policy callbacks were installed/rebound with a view generation
    /// that the host router does not currently consider live.
    PolicyViewGone,
    /// A bound session was asked to rebind to a different slot. A binding
    /// is per-slot identity; adopting another slot's id is the arbitrary
    /// reassignment that binding exists to prevent.
    ForeignRebind,
    /// A bound session was asked to rebind to a new generation of its own slot
    /// while the previously-bound generation is still live.
    /// A rebind is legal only as owned recovery, i.e. after the old generation
    /// died.
    RebindWhileLive,
    /// The input-method seam could not be installed on this view. Loud, because
    /// a silently IME-less view looks exactly like a page that never focused an
    /// input.
    ImeInstall(crate::ffi::ime::ImeInstallError),
    /// The destination guard could not be started; no unguarded view is made.
    DestinationGuardUnavailable(String),
    /// The WPE WebProcess did not load and acknowledge the synchronous
    /// pre-network credential guard; no caller-controlled page is loaded.
    CredentialGuardUnavailable(String),
    /// A host-initiated load was refused before WebKit could issue a request.
    DestinationRefused(crate::web::DestinationDenial),
    /// A native WebKit signal returned handler id 0 (unknown/renamed signal),
    /// so the session construction was refused rather than exposing a view
    /// whose policy/lifecycle callback was silently absent. Carries
    /// the exact signal name that could not be connected.
    NativeSignalBindFailed(&'static str),
    /// A TLS certificate could not be parsed from PEM data or the host
    /// contained an interior NUL.
    TlsCertificateError(String),
}

/// Why a host→page IME command was refused before reaching WebKit.
///
/// Exhaustive on purpose: every variant means "nothing was typed into any
/// page", and a future variant absorbed by a wildcard arm would be read as
/// success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImeCommandError {
    /// The seam was never installed - [`WebSession::enable_input_method`] was
    /// not called.
    NotEnabled,
    /// This session has no [`ViewId`](crate::web::ViewId), so a
    /// view-scoped command cannot be attributed to it.
    ViewNotBound,
    /// The command named a different view than the one this session is bound
    /// to. Two sessions can both be live, so the router check alone cannot
    /// separate them.
    ForeignSession {
        /// The id this session is bound to.
        bound: crate::web::ViewId,
        /// The id the command named.
        asked: crate::web::ViewId,
    },
    /// The named generation is no longer the router's live one: the page died
    /// and was recreated between the keystroke and the commit.
    ViewNotLive {
        /// The id the command named.
        view: crate::web::ViewId,
    },
    /// No editable element holds focus in the page, so there is nowhere to
    /// commit. Refused rather than emitted, because WebKit would route the
    /// commit to whatever gains focus next.
    NoFocusedField,
}

/// Why a widget viewport resize did not reach this session's WPE toplevel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewportResizeError {
    /// This session has not been bound to a router-minted view generation.
    ViewNotBound,
    /// The request names a different session or generation.
    ForeignSession {
        /// This session's bound generation.
        bound: crate::web::ViewId,
        /// The generation carried by the request.
        asked: crate::web::ViewId,
    },
    /// The request's generation is no longer live in the router.
    ViewNotLive {
        /// The stale generation that was requested.
        view: crate::web::ViewId,
    },
    /// The WPE view does not currently expose a toplevel to resize.
    NoToplevel,
    /// The selected WPE platform backend does not support this resize.
    Unsupported,
}

/// What a successful [`WebSession::resize_viewport`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewportResize {
    /// A new integer logical size was sent to WPEPlatform.
    Requested,
    /// This exact generation and integer size was already requested.
    Unchanged,
}

/// Why WebKit's process for a view terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebProcessTermination {
    /// The WebProcess crashed.
    Crashed,
    /// WebKit killed it for exceeding its memory limit.
    ExceededMemoryLimit,
    /// The host requested termination through the API.
    TerminatedByApi,
    /// A newer runtime reported a reason this binding does not know yet.
    Unknown(i32),
}

#[derive(Debug)]
struct TerminationState {
    reason: std::cell::Cell<Option<WebProcessTermination>>,
    count: std::cell::Cell<u64>,
}

extern "C" fn on_web_process_terminated(
    _web_view: *mut ffi::WebKitWebView,
    reason: c_int,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the live box owned by WebSession; Drop disconnects
    // this signal before freeing it.
    let state = unsafe { &*(user_data as *const TerminationState) };
    let reason = match reason {
        0 => WebProcessTermination::Crashed,
        1 => WebProcessTermination::ExceededMemoryLimit,
        2 => WebProcessTermination::TerminatedByApi,
        other => WebProcessTermination::Unknown(other),
    };
    state.reason.set(Some(reason));
    state.count.set(state.count.get().wrapping_add(1));
}

/// A persistent WebKit view bound to a headless display, able to load pages,
/// receive synthesized input, and snapshot.
///
/// Not `Send`/`Sync`: WebKit + GLib are thread-affine (the default main
/// context belongs to the constructing thread).
struct ProxyAuthenticationState {
    host: CString,
    port: u32,
    username: CString,
    password: CString,
}

struct ProxyAuthenticationBinding {
    web_view: *mut ffi::WebKitWebView,
    handler: u64,
    state: *mut ProxyAuthenticationState,
}

pub struct WebSession {
    web_view: *mut ffi::WebKitWebView,
    /// The app profile identity, when this view was explicitly profiled.
    profile: Option<crate::web::WebProfile>,
    /// Keeps the exact storage/network-policy session supplied through the
    /// construct-only property alive for at least as long as the view.
    network_session: Option<Rc<crate::ffi::profile::NetworkSession>>,
    /// Borrowed - owned by `web_view`, never unref'd here.
    pub(super) wpe_view: *mut ffi::WPEView,
    pub(super) gpu_presentation: Option<crate::ffi::presentation::PresentationBinding>,
    /// Borrowed - the view's accessibility object, owned by the
    /// view. NULL if the platform exposes none. Never unref'd here.
    accessible: *mut ffi::WPEViewAccessible,
    /// Box shared with the `web-process-terminated` signal callback.
    termination_state: *mut TerminationState,
    termination_handler: u64,
    proxy_authentication: Option<ProxyAuthenticationBinding>,
    /// Generation-scoped handlers for WebKit's native policy signals. The
    /// constructor installs strict defaults, so caller omission stays safe.
    native_policy: Option<crate::ffi::policy::NativePolicyBinding>,
    /// The destination policy enforced by the native callbacks and the
    /// network-session-owned guard.
    destination_policy: crate::web::DestinationPolicy,
    /// The installed input-method seam, when the host enabled
    /// it. Dropped explicitly before `web_view` is unref'd: its `Drop` detaches
    /// the context from the view first, so WebKit cannot call a vfunc on a
    /// released object.
    ime: Option<crate::ffi::ime::ImeContext>,
    /// This session's own [`ViewId`], when the host has bound
    /// one. A page-accessibility delivery or a routed action naming any other
    /// id is refused before the tree is walked or the action performed,
    /// even if that other id is itself live in the router. Two live sessions
    /// in different slots are both `accepts`-true, so the router check alone
    /// cannot tell them apart; the binding is what stops session A publishing
    /// its tree under session B's id (the two-session mislabel).
    bound_view: Option<crate::web::ViewId>,
    page_copy_serial: std::cell::Cell<u64>,
    favicon_identity: Rc<std::cell::Cell<Option<crate::web::ViewId>>>,
    favicon_lifetime: Rc<()>,
    /// The native-owned action authority. Seeded only by this
    /// session's own AT-SPI walk in [`deliver_page_accessibility`]; it is the
    /// sole source of the object and index that reach `Action.DoAction`, so a
    /// caller-supplied tree can never choose a native action.
    native_authority: crate::page_delivery::NativeActionAuthority,
    /// The WebProcess identities that already existed when this session was
    /// constructed. Attestation excludes them, so this session's verdict is
    /// about its renderer rather than the worst renderer in the process
    ///: condemning - and trying to terminate - another view's renderer
    /// would both spare the offender and kill an innocent page.
    sandbox_baseline: Vec<crate::sandbox::ProcessIdentity>,
    /// The renderer identity this session attested, if any. `Cell` so the
    /// enforced navigation check can refresh it through `&self`.
    attested_renderer: std::cell::Cell<Option<crate::sandbox::ProcessIdentity>>,
    attested_after_terminations: std::cell::Cell<u64>,
    renderer_liveness:
        std::cell::RefCell<Option<crate::sandbox::process_liveness::ProcessLiveness>>,
    /// The outer-sandbox policy this session was constructed under.
    /// Threaded into both preflight and postflight so
    /// [`crate::sandbox::OuterSandbox::AcceptedByHost`] is reachable in
    /// production rather than a claim with no path to it.
    sandbox_policy: crate::sandbox::OuterSandbox,
    /// Whether snapshots paint the page's text selection (on by default: an
    /// interactive session shows what the user selected).
    snapshot_selection: bool,
    /// Last generation+integer viewport request. The retained value suppresses
    /// same-size redraw traffic while still forwarding the same dimensions to
    /// a replacement generation.
    last_viewport_request: Option<(crate::web::ViewId, crate::viewport::ViewportSize)>,
    /// The page-event queue, shared with the policy binding (redirect
    /// capture, allowed popups) and the page binding.
    page_hub: std::rc::Rc<crate::ffi::page::PageHub>,
    pdf_exports: session_print::PdfExportRegistry,
    /// Page signals (load, address, title, prompts, scripts, find). Connected
    /// after the inert bootstrap, so the host never sees the bootstrap load.
    page: Option<crate::ffi::page::PageBinding>,
    /// The local inspector frontend, while the host has it bound.
    pub(super) inspector: std::cell::RefCell<Option<session_inspector::InspectorFrontend>>,
    _not_send_sync: PhantomData<*const c_void>,
}

// WebSession implementation is split by responsibility; the type and all
// public paths remain in this parent module.
mod browser_cookies;
#[path = "content_filters.rs"]
pub mod content_filters;
mod error_display;
mod ready_wait;
pub use browser_cookies::{CookieInfo, CookieKey};
mod session_clipboard;
mod session_data;
mod session_discard;
mod session_export;
mod session_favicon;
mod session_focus;
pub use session_export::PageExportTask;
pub use session_favicon::FaviconTask;
mod application_id;
mod back_forward_cache;
mod gpu_process;
mod process_cache;
mod process_memory;
#[path = "resource_log.rs"]
pub mod resource_log;
mod session_history;
mod session_ime;
mod session_input;
mod session_inspector;
mod session_lifecycle;
mod spare_process;
pub use session_lifecycle::PendingWebSession;
mod session_memory;
mod session_page;
mod session_permissions;
mod session_print;
pub use application_id::set_application_id;
pub use back_forward_cache::{
    BackForwardCachePolicy, BackForwardCacheUnsupported, clear_back_forward_cache,
    set_back_forward_cache,
};
pub use gpu_process::{set_gpu_process_for_compositing, set_gpu_process_for_webgl};
pub use process_cache::{
    ProcessCacheUnsupported, WebProcessCachePolicy, clear_web_process_cache, set_web_process_cache,
};
pub use process_memory::{
    ProcessMemoryBudgetsUnsupported, RendererProcessIdUnsupported, release_host_allocator_memory,
    release_resident_pages, set_process_memory_budgets,
};
pub use session_discard::DiscardedPage;
pub use session_inspector::InspectorError;
pub use session_memory::MemoryReleaseUnsupported;
pub use session_page::ConnectionTlsInfo;
pub use spare_process::{SpareProcessUnsupported, set_spare_web_process};

pub use session_clipboard::{PageSelection, PendingPageCopy};
use session_lifecycle::run_load_on_view;
pub use session_lifecycle::{INPUT_REPAINT_WINDOW, MAX_HTML_DOCUMENT_BYTES};

/// Why a page-accessibility delivery was refused .
#[derive(Debug)]
pub enum DeliverError {
    /// The offered `view` is not this session's bound id, even though it may be
    /// live in the router: session A must not publish under session B's id.
    ForeignSession {
        /// This session's own bound id.
        bound: crate::web::ViewId,
        /// The (foreign) id the caller asked to deliver under.
        asked: crate::web::ViewId,
    },
    /// The session was never bound to a view, so a view-scoped delivery has no
    /// owner to check against.
    ViewNotBound,
    /// The bound id matches `view` but the router no longer considers it live
    /// because the session is bound to a superseded generation and a
    /// walk is refused before it is attempted.
    ViewNotLive {
        /// The stale id the session is still bound to.
        view: crate::web::ViewId,
    },
    /// The AT-SPI walk itself failed.
    Walk(crate::ffi::a11y::A11yError),
}

/// Why a routed page action was not performed.
#[derive(Debug)]
pub enum PageActionError {
    /// The `live` id naming the action is not this session's bound id, even
    /// though it may be live in the router.
    ForeignSession {
        /// This session's own bound id.
        bound: crate::web::ViewId,
        /// The (foreign) id the caller asked to act under.
        asked: crate::web::ViewId,
    },
    /// The session was never bound to a view.
    ViewNotBound,
    /// The delivery layer refused to route it: not live, no page, a stale page,
    /// an unknown node, or a node that is not operable. Carried verbatim so the
    /// caller can tell a hostile request from a page that simply changed.
    NotRouted(crate::page_delivery::PageActionRoute),
    /// The resolved action's name is not on
    /// [`ACTIVATION_ACTIONS`](crate::page_a11y::ACTIVATION_ACTIONS). Reaching
    /// this means the resolver and the executor disagree, so nothing is
    /// performed.
    NotAnActivation(String),
    /// The action index does not fit AT-SPI's `i32`.
    IndexOutOfRange(usize),
    /// The action authority refused to authorize a native `DoAction`: the
    /// asking view is not live, no native walk has run, the walk is superseded,
    /// or the node was never recorded as natively
    /// actionable (including a node that existed only in a caller-supplied
    /// inert tree). Carries the typed reason. An external
    /// [`AccessibleSource`](crate::page_a11y::AccessibleSource) can build a tree
    /// for display and delivery-layer routing, but the object/index that would
    /// reach the bus are read from native-owned state, so a forged or cloned
    /// address can never drive a real action.
    NotNativelyAuthorized(crate::page_delivery::NativeActionRefusal),
    /// The AT-SPI call itself failed.
    Bus(crate::ffi::a11y::A11yError),
}

unsafe extern "C" {
    /// `void g_signal_handler_disconnect (gpointer instance, gulong handler_id);`
    ///
    /// Disconnects a previously-connected signal handler so it cannot fire
    /// again. Used to detach the per-load `load-changed` handler before its
    /// boxed state is freed.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gsignal.h`
    fn g_signal_handler_disconnect(instance: *mut c_void, handler_id: u64);
}
