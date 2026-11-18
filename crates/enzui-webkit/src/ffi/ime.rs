//! The WPE input-method seam: a `WebKitInputMethodContext` subclass that
//! observes the focused page field and commits compositions into it.
//!

use super::wpe;
use core::ffi::{c_char, c_int, c_uint, c_void};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;

// The vfunc slots are written by field access, so the mirrored class layout
// must match the C one. Pinned by a C `offsetof` probe against
// `WebKitInputMethodContext.h` (WPE WebKit 2.52.5, x86_64). A struct reorder or
// a different GObjectClass size fails the build instead of overwriting the
// wrong vfunc - which here would mean handing WebKit the caret recorder as its
// `committed` signal handler.
const _: () = {
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, set_enable_preedit) == 176,
        "WebKitInputMethodContextClass::set_enable_preedit must be at offset 176"
    );
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, get_preedit) == 184,
        "WebKitInputMethodContextClass::get_preedit must be at offset 184"
    );
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, notify_focus_in) == 200,
        "WebKitInputMethodContextClass::notify_focus_in must be at offset 200"
    );
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, notify_focus_out) == 208,
        "WebKitInputMethodContextClass::notify_focus_out must be at offset 208"
    );
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, notify_cursor_area) == 216,
        "WebKitInputMethodContextClass::notify_cursor_area must be at offset 216"
    );
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, notify_surrounding) == 224,
        "WebKitInputMethodContextClass::notify_surrounding must be at offset 224"
    );
    assert!(
        core::mem::offset_of!(wpe::WebKitInputMethodContextClass, reset) == 232,
        "WebKitInputMethodContextClass::reset must be at offset 232"
    );
};

/// The registered type name. Includes the crate so two frameworks in one
/// process cannot collide.
const TYPE_NAME: &str = "EnzUiIcedWebImeContext";

/// Ceiling on the page-controlled surrounding-text buffer this code will decode and
/// retain, in bytes.
///
/// `notify_surrounding`'s `length` is set by the focused DOM field, so it is
/// attacker-controlled: a hostile page can grow its editable value to hundreds
/// of MiB and force a fresh `from_utf8_lossy(..).into_owned()` of that size on
/// every surrounding-text refresh, one copy of which is then retained in IME
/// state. An input method only ever needs *local* context around the caret -
/// WebKit itself computes the surrounding window from a bounded neighbourhood,
/// and real IMEs consult at most a sentence or two. 64 KiB of UTF-8 is tens of
/// thousands of characters: far past any genuine editing context, while keeping
/// each refresh's allocation bounded regardless of the page's field size.
const MAX_SURROUNDING_BYTES: usize = 64 * 1024;

/// What the page reported about its focused field, as reported by real
/// WebKit vfunc calls.
///
/// Every field is `Option`/counted so "the page never said" is distinguishable
/// from "the page said zero" - the difference between an unimplemented seam and
/// a caret at the origin.
#[derive(Clone, Default)]
pub struct PageImeReport {
    /// Whether an editable element currently holds DOM focus.
    pub focused: bool,
    /// The caret rectangle in logical view pixels, as last reported by
    /// `notify_cursor_area`. `None` until the page reports one, and cleared on
    /// focus-out so a blurred field publishes no geometry.
    pub caret: Option<(i32, i32, i32, i32)>,
    /// The raw `WebKitInputPurpose` value read off the context at focus-in.
    pub purpose: c_int,
    /// The raw `WebKitInputHints` bitmask read off the context at focus-in.
    pub hints: c_uint,
    /// The text around the caret, and the caret/selection byte offsets into it.
    pub surrounding: Option<(String, u32, u32)>,
    /// Whether WebKit asked for on-the-spot preedit.
    pub preedit_enabled: bool,
    /// How many times WebKit called `reset`. A counter rather than a flag so a
    /// test can tell one reset from three.
    pub resets: u64,
    /// How many times `notify_focus_in` fired. Distinguishes a re-focus from a
    /// caret move within one focus.
    pub focus_ins: u64,
    /// How many times `notify_focus_out` fired.
    pub focus_outs: u64,
    /// The composition being shown, handed back through `get_preedit`.
    /// `(text, cursor_offset_in_chars)`.
    pub preedit: Option<(String, u32)>,
}

impl fmt::Debug for PageImeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let surrounding = self.surrounding.as_ref().map(|(text, cursor, selection)| {
            (crate::web::redacted_ime_text(text), *cursor, *selection)
        });
        let preedit = self
            .preedit
            .as_ref()
            .map(|(text, cursor)| (crate::web::redacted_ime_text(text), *cursor));
        formatter
            .debug_struct("PageImeReport")
            .field("focused", &self.focused)
            .field("caret", &self.caret)
            .field("purpose", &self.purpose)
            .field("hints", &self.hints)
            .field("surrounding", &surrounding)
            .field("preedit_enabled", &self.preedit_enabled)
            .field("resets", &self.resets)
            .field("focus_ins", &self.focus_ins)
            .field("focus_outs", &self.focus_outs)
            .field("preedit", &preedit)
            .finish()
    }
}

thread_local! {
    /// Per-context state, keyed by instance pointer. Thread-local because the
    /// whole WPE runtime is thread-affine, so no lock is needed and none would
    /// be honest about the constraint.
    static STATE: RefCell<HashMap<usize, PageImeReport>> = RefCell::new(HashMap::new());

    /// The registered GType, once. Zero means "not yet registered".
    static REGISTERED: std::cell::Cell<wpe::GType> = const { std::cell::Cell::new(0) };
}

/// Read-modify-write one context's row, creating it if absent.
fn with_state<R>(
    ctx: *mut wpe::WebKitInputMethodContext,
    f: impl FnOnce(&mut PageImeReport) -> R,
) -> R {
    let key = ctx as usize;
    STATE.with(|m| {
        let mut map = m.borrow_mut();
        f(map.entry(key).or_default())
    })
}

/// Non-panicking variant of [`with_state`] for `extern "C"` vfuncs.
///
/// Returns `None` when the thread-local state map is already borrowed
/// (re-entrant GObject callback). A panic inside an `extern "C"` fn aborts
/// the process; this returns `None` so the vfunc degrades to a no-op instead.
/// Safe-Rust callers keep the panicking [`with_state`] because re-entrancy
/// there is a programming error that should propagate normally.
fn try_with_state<R>(
    ctx: *mut wpe::WebKitInputMethodContext,
    f: impl FnOnce(&mut PageImeReport) -> R,
) -> Option<R> {
    let key = ctx as usize;
    STATE.with(|m| {
        let mut map = m.try_borrow_mut().ok()?;
        Some(f(map.entry(key).or_default()))
    })
}

// ---------------------------------------------------------------------------
// The overridden vfuncs. Each is installed only as the matching slot of its own
// subclass's vtable, so WebKit calls it with a live instance of the type.
// ---------------------------------------------------------------------------

/// `notify_focus_in`: an editable element got DOM focus. Read the purpose and
/// hints WebKit set on this context before calling, so the host learns "password" at the
/// same moment it learns "focused".
extern "C" fn on_focus_in(ctx: *mut wpe::WebKitInputMethodContext) {
    // SAFETY: `ctx` is a live instance of the subclass; both getters are plain
    // property reads on it.
    let (purpose, hints) = unsafe {
        (
            wpe::webkit_input_method_context_get_input_purpose(ctx),
            wpe::webkit_input_method_context_get_input_hints(ctx),
        )
    };
    let _ = try_with_state(ctx, |s| {
        s.focused = true;
        s.focus_ins += 1;
        s.purpose = purpose;
        s.hints = hints;
    });
}

/// `notify_focus_out`: the element blurred. The caret is cleared with the
/// focus: a stale rectangle left behind is exactly the "publish stale geometry"
/// defect, and clearing it here means the host cannot publish one even if it
/// forgets to close its own IME.
extern "C" fn on_focus_out(ctx: *mut wpe::WebKitInputMethodContext) {
    let _ = try_with_state(ctx, |s| {
        s.focused = false;
        s.focus_outs += 1;
        s.caret = None;
        s.surrounding = None;
        s.preedit = None;
    });
}

/// `notify_cursor_area`: the caret rectangle, in logical view pixels.
///
/// WebKit applies `platformTransformCursorRectToViewCoordinates` before this
/// call and the WPE port's version is the identity, and its source is the
/// logical root-view `caretRectAtStart`, so the numbers are logical view
/// pixels: page zoom is applied (it changes layout) but the output/device
/// scale is not. Measured both ways by the native gate - doubling under
/// page zoom 2, and unchanged under a forced `wpe_view_get_scale() == 2` - not
/// assumed.
///
/// WebKit also suppresses moves shorter than 10 px
/// (`InputMethodFilter::notifyCursorRect`'s `windowMovementThreshold`), so a
/// refocus that lands the caret where it already was reports nothing at all.
extern "C" fn on_cursor_area(
    ctx: *mut wpe::WebKitInputMethodContext,
    x: c_int,
    y: c_int,
    w: c_int,
    h: c_int,
) {
    let _ = try_with_state(ctx, |s| {
        s.caret = Some((x, y, w, h));
    });
}

/// Decode a `notify_surrounding` payload into bounded, valid IME state.
///
/// Split out from the `extern "C"` shim so the ceiling, the UTF-8 validation
/// and the offset clamping are testable without fabricating a raw pointer:
/// this is the whole decision, and the shim above it only produces the slice.
///
/// * `bytes` is the `length`-byte window WebKit reported - never a NUL scan.
///   A pointer+length callback is not made safe by looking for a terminator
///   first, so the terminator is never consulted. The page controls `length`,
///   so it is capped to [`MAX_SURROUNDING_BYTES`] before any allocation.
/// * invalid UTF-8 is replaced rather than trusted (`from_utf8_lossy`), because
///   a page can put lone surrogates through the DOM.
/// * `cursor_index`/`selection_index` are byte offsets *into that buffer*. They
///   are clamped to the decoded string's length and then floored to the nearest
///   char boundary, so no later slice of `surrounding` can panic.
fn decode_surrounding(bytes: &[u8], cursor_index: u32, selection_index: u32) -> (String, u32, u32) {
    // Bound the page-controlled buffer BEFORE the decoding allocation. Without
    // this ceiling a focused DOM field of arbitrary size drives an unbounded
    // `into_owned()` copy that is then retained in IME state. The cap is
    // applied here, at the one place the bytes are turned into an allocation, so
    // the raw slice the shim built is never read past the ceiling.
    let capped = if bytes.len() > MAX_SURROUNDING_BYTES {
        // Genuine truncation: drop a trailing partial UTF-8 sequence so the cut
        // lands on a real char boundary rather than manufacturing a replacement
        // character purely from where the ceiling fell. Interior invalid bytes
        // are still lossy-replaced below; only the truncation seam is trimmed.
        trim_incomplete_tail(&bytes[..MAX_SURROUNDING_BYTES])
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(capped).into_owned();
    let floor = |raw: u32| {
        let mut i = (raw as usize).min(text.len());
        while i > 0 && !text.is_char_boundary(i) {
            i -= 1;
        }
        u32::try_from(i).unwrap_or(u32::MAX)
    };
    let cursor = floor(cursor_index);
    let selection = floor(selection_index);
    (text, cursor, selection)
}

/// Drop a trailing *incomplete* UTF-8 sequence from a truncated buffer so the
/// slice ends on a char boundary.
///
/// Only used on the ceiling-truncated window: it walks back at most the four
/// bytes a maximal UTF-8 scalar can occupy, finds the last lead byte, and cuts
/// there iff the sequence it starts cannot fit in the retained bytes. A
/// complete trailing scalar (or an invalid lead byte, left for `from_utf8_lossy`
/// to replace) is returned unchanged.
fn trim_incomplete_tail(bytes: &[u8]) -> &[u8] {
    let end = bytes.len();
    let start = end.saturating_sub(4);
    let mut i = end;
    while i > start {
        i -= 1;
        let b = bytes[i];
        // Continuation byte (10xxxxxx): keep scanning toward the lead byte.
        if b & 0b1100_0000 == 0b1000_0000 {
            continue;
        }
        // Lead (or ASCII) byte: how many bytes should this scalar occupy?
        let expected = if b < 0x80 {
            1
        } else if b >> 5 == 0b110 {
            2
        } else if b >> 4 == 0b1110 {
            3
        } else if b >> 3 == 0b1_1110 {
            4
        } else {
            // Invalid lead byte: not a truncation artefact, leave it for lossy.
            1
        };
        return if i + expected <= end {
            bytes
        } else {
            &bytes[..i]
        };
    }
    // No lead byte within the last four bytes (all continuation/garbage): leave
    // it for `from_utf8_lossy` rather than guessing.
    bytes
}

/// `notify_surrounding`: the text around the caret plus byte offsets. Needed so
/// a delete-surrounding request can be expressed in the page's own terms.
extern "C" fn on_surrounding(
    ctx: *mut wpe::WebKitInputMethodContext,
    text: *const c_char,
    length: c_uint,
    cursor_index: c_uint,
    selection_index: c_uint,
) {
    let decoded = if text.is_null() || length == 0 {
        (String::new(), 0, 0)
    } else {
        // SAFETY: WebKit's contract for this vfunc is a buffer of `length`
        // bytes at `text`, live for the duration of the call. Constructing the
        // slice does not read memory; `decode_surrounding` reads and allocates
        // at most `MAX_SURROUNDING_BYTES` of it, so a page-inflated `length`
        // cannot drive an unbounded copy. The buffer is never assumed
        // NUL-terminated.
        let bytes = unsafe { core::slice::from_raw_parts(text.cast::<u8>(), length as usize) };
        decode_surrounding(bytes, cursor_index, selection_index)
    };
    let _ = try_with_state(ctx, |s| {
        s.surrounding = Some(decoded);
    });
}

/// `set_enable_preedit`: whether the field can show a composition on the spot.
extern "C" fn on_set_enable_preedit(
    ctx: *mut wpe::WebKitInputMethodContext,
    enabled: wpe::GBoolean,
) {
    let _ = try_with_state(ctx, |s| {
        s.preedit_enabled = enabled != wpe::G_FALSE;
    });
}

/// `get_preedit`: WebKit reading the composition advertised.
///
/// The string must come from glib's allocator because WebKit `g_free`s it.
/// `underlines` is left NULL (no styling), which is the documented "no
/// underlines" answer rather than an empty list this code would have to free.
///
/// Every out-parameter receives a safe default before fallible work, so a
/// borrow failure still leaves WebKit with a valid empty composition.
extern "C" fn on_get_preedit(
    ctx: *mut wpe::WebKitInputMethodContext,
    text: *mut *mut c_char,
    underlines: *mut *mut wpe::GList,
    cursor_offset: *mut c_uint,
) {
    // SAFETY: each non-null out-parameter is a live pointer supplied by
    // WebKit for this call.  Defaults are written before fallible work so a
    // borrow failure still leaves every parameter valid.
    if !underlines.is_null() {
        unsafe { *underlines = core::ptr::null_mut() };
    }
    if !cursor_offset.is_null() {
        unsafe { *cursor_offset = 0 };
    }
    if !text.is_null() {
        unsafe { *text = wpe::g_strdup(c"".as_ptr()) };
    }

    let held = try_with_state(ctx, |s| s.preedit.clone()).flatten();
    let Some((content, offset)) = held else {
        return;
    };

    if !cursor_offset.is_null() {
        unsafe { *cursor_offset = offset };
    }
    if text.is_null() {
        return;
    }
    let c = CString::new(content).unwrap_or_default();
    // SAFETY: free the glib-allocated default, then write the real value.
    unsafe {
        wpe::g_free((*text).cast::<c_void>());
        *text = wpe::g_strdup(c.as_ptr());
    };
}

/// `reset`: the engine cancelled composition (navigation, programmatic blur).
extern "C" fn on_reset(ctx: *mut wpe::WebKitInputMethodContext) {
    let _ = try_with_state(ctx, |s| {
        s.resets += 1;
        s.preedit = None;
    });
}

/// `GClassInitFunc` for the subclass: write the vfuncs into its own copy of
/// the vtable.
extern "C" fn class_init(class: *mut c_void, _data: *mut c_void) {
    let class = class.cast::<wpe::WebKitInputMethodContextClass>();
    if class.is_null() {
        return;
    }
    // SAFETY: glib hands over its own class struct, allocated at the size
    // `g_type_query` reported for the parent, so every slot below is inside the
    // allocation (the last one written is at offset 232 of a 368-byte struct).
    unsafe {
        (*class).notify_focus_in = Some(on_focus_in as wpe::ImeNotifyFn);
        (*class).notify_focus_out = Some(on_focus_out as wpe::ImeNotifyFn);
        (*class).notify_cursor_area = Some(on_cursor_area as wpe::ImeNotifyCursorAreaFn);
        (*class).notify_surrounding = Some(on_surrounding as wpe::ImeNotifySurroundingFn);
        (*class).set_enable_preedit = Some(on_set_enable_preedit as wpe::ImeSetEnablePreeditFn);
        (*class).get_preedit = Some(on_get_preedit as wpe::ImeGetPreeditFn);
        (*class).reset = Some(on_reset as wpe::ImeNotifyFn);
    }
}

/// Register (once) and return the IME context GType.
///
/// Idempotent by name lookup rather than by a bare flag, so it is still correct
/// if a second copy of this crate is linked into the same process: glib would
/// emit a critical for a duplicate registration, and reusing the existing type
/// is both quieter and correct.
fn context_type() -> wpe::GType {
    let cached = REGISTERED.with(std::cell::Cell::get);
    if cached != 0 {
        return cached;
    }
    let name = CString::new(TYPE_NAME).expect("static name, no NUL");
    // SAFETY: plain glib type-system lookups.
    let existing = unsafe { wpe::g_type_from_name(name.as_ptr()) };
    if existing != 0 {
        REGISTERED.with(|c| c.set(existing));
        return existing;
    }
    // SAFETY: `webkit_input_method_context_get_type` initialises the parent
    // type; `g_type_query` then reports its real class/instance sizes.
    let parent = unsafe { wpe::webkit_input_method_context_get_type() };
    let mut query = wpe::GTypeQuery::default();
    // SAFETY: `query` is a live, zeroed GTypeQuery.
    unsafe { wpe::g_type_query(parent, &mut query) };
    if query.class_size == 0 || query.instance_size == 0 {
        // Not a classed type - refuse rather than register a bogus size.
        return 0;
    }
    // SAFETY: sizes come from glib itself; `class_init` writes only slots inside
    // `class_size`; no instance_init is needed because per-instance state lives
    // in a side table.
    let registered = unsafe {
        wpe::g_type_register_static_simple(
            parent,
            name.as_ptr(),
            query.class_size,
            Some(class_init),
            query.instance_size,
            None,
            0,
        )
    };
    REGISTERED.with(|c| c.set(registered));
    registered
}

/// Why installing the input-method seam failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImeInstallError {
    /// The `WebKitInputMethodContext` subclass could not be registered (the
    /// parent type is not classed - an ABI change, not a runtime condition).
    TypeRegistrationFailed,
    /// `g_object_new_with_properties` returned NULL.
    ContextConstructionFailed,
    /// The view did not accept the context: reading it back returned a
    /// different pointer. Refused rather than left silently IME-less, which
    /// would look exactly like "the page never focused an input".
    NotInstalled,
    /// A signal the seam must emit does not exist on the context type.
    SignalMissing,
}

impl core::fmt::Display for ImeInstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ImeInstallError::TypeRegistrationFailed => {
                write!(
                    f,
                    "could not register the WebKitInputMethodContext subclass"
                )
            }
            ImeInstallError::ContextConstructionFailed => {
                write!(f, "could not construct the input method context")
            }
            ImeInstallError::NotInstalled => write!(
                f,
                "the web view did not accept the input method context (read-back mismatch)"
            ),
            ImeInstallError::SignalMissing => {
                write!(
                    f,
                    "a required input-method signal is absent from the context type"
                )
            }
        }
    }
}

impl std::error::Error for ImeInstallError {}

/// The signal ids the seam emits, resolved once at install so a typo is a
/// typed error rather than a dropped emission.
#[derive(Debug, Clone, Copy)]
struct SignalIds {
    preedit_started: c_uint,
    preedit_changed: c_uint,
    preedit_finished: c_uint,
    committed: c_uint,
    delete_surrounding: c_uint,
}

/// An installed input-method context, owned by a session.
///
/// Dropping it detaches the context from the view before unref'ing, and
/// removes the side-table row, so neither WebKit nor a recycled pointer can
/// reach dead state.
pub struct ImeContext {
    ctx: *mut wpe::WebKitInputMethodContext,
    web_view: *mut wpe::WebKitWebView,
    /// The registered subclass's GType. Needed to `g_value_init` the instance
    /// slot of every emission array: `g_value_set_instance` collects through
    /// the value table of the value's ALREADY-SET type, so an uninitialised
    /// GValue makes it a no-op that glib reports as `type id '0' is invalid`
    /// and the signal never reaches WebKit.
    gtype: wpe::GType,
    signals: SignalIds,
}

impl ImeContext {
    /// Register the subclass, construct a context, and install it on
    /// `web_view`, verifying the installation by read-back.
    ///
    /// # Safety
    ///
    /// `web_view` must be a live `WebKitWebView*` that outlives the returned
    /// value (a session holds both, and drops this first).
    pub unsafe fn install(
        web_view: *mut wpe::WebKitWebView,
    ) -> Result<ImeContext, ImeInstallError> {
        let gtype = context_type();
        if gtype == 0 {
            return Err(ImeInstallError::TypeRegistrationFailed);
        }
        // SAFETY: zero properties; the arrays are unread at count 0.
        let ctx = unsafe {
            wpe::g_object_new_with_properties(gtype, 0, core::ptr::null(), core::ptr::null())
        }
        .cast::<wpe::WebKitInputMethodContext>();
        if ctx.is_null() {
            return Err(ImeInstallError::ContextConstructionFailed);
        }

        let lookup = |name: &str| -> c_uint {
            let c = CString::new(name).expect("static signal name, no NUL");
            // SAFETY: plain signal lookup on a registered type.
            unsafe { wpe::g_signal_lookup(c.as_ptr(), gtype) }
        };
        let signals = SignalIds {
            preedit_started: lookup("preedit-started"),
            preedit_changed: lookup("preedit-changed"),
            preedit_finished: lookup("preedit-finished"),
            committed: lookup("committed"),
            delete_surrounding: lookup("delete-surrounding"),
        };
        if signals.preedit_started == 0
            || signals.preedit_changed == 0
            || signals.preedit_finished == 0
            || signals.committed == 0
            || signals.delete_surrounding == 0
        {
            // SAFETY: `ctx` is owned here, rc=1, never installed.
            unsafe { wpe::g_object_unref(ctx.cast::<c_void>()) };
            return Err(ImeInstallError::SignalMissing);
        }

        // SAFETY: both pointers are live; the view takes its own reference.
        unsafe { wpe::webkit_web_view_set_input_method_context(web_view, ctx) };
        // SAFETY: live view; the returned pointer is borrowed.
        let installed = unsafe { wpe::webkit_web_view_get_input_method_context(web_view) };
        if installed != ctx {
            // SAFETY: detach whatever this code may have set, then drop the reference.
            unsafe {
                wpe::webkit_web_view_set_input_method_context(web_view, core::ptr::null_mut());
                wpe::g_object_unref(ctx.cast::<c_void>());
            }
            return Err(ImeInstallError::NotInstalled);
        }
        // Seed the row so a read before any callback is "focused: false" rather
        // than an absent entry.
        with_state(ctx, |_| ());
        Ok(ImeContext {
            ctx,
            web_view,
            gtype,
            signals,
        })
    }

    /// What the real page has reported so far.
    ///
    /// # Purpose and hints are read live, not remembered
    ///
    /// `notify_focus_in` records them too, but WebKit sets the `input-purpose`
    /// / `input-hints` properties from the editor state on its own
    /// schedule, which is not guaranteed to precede the focus-in call. Reading
    /// them here, at the moment the host asks, is the only ordering-independent
    /// answer - and it is a plain property read on a live object, so it costs
    /// nothing. A purpose latched at focus-in was measured as always
    /// `FREE_FORM` on WPE 2.52 even for a real password field.
    #[must_use]
    pub fn report(&self) -> PageImeReport {
        let key = self.ctx as usize;
        let mut report = STATE.with(|m| m.borrow().get(&key).cloned().unwrap_or_default());
        // SAFETY: `self.ctx` is a live instance of the subclass for as long as
        // this `ImeContext` exists; both are plain property getters.
        unsafe {
            report.purpose = wpe::webkit_input_method_context_get_input_purpose(self.ctx);
            report.hints = wpe::webkit_input_method_context_get_input_hints(self.ctx);
        }
        report
    }

    pub(crate) fn native_report(&self) -> crate::ime_bridge::NativeImeReport {
        // Host routing needs only scalar metadata, not copies of surrounding or preedit text.
        let mut report = STATE.with(|states| {
            states
                .borrow()
                .get(&(self.ctx as usize))
                .map(|state| crate::ime_bridge::NativeImeReport {
                    focused: state.focused,
                    caret: state.caret,
                    purpose: state.purpose,
                })
                .unwrap_or_default()
        });
        // SAFETY: the context is live on its owning thread. Purpose is read live,
        // as in report(), after releasing the state-table borrow.
        report.purpose = unsafe { wpe::webkit_input_method_context_get_input_purpose(self.ctx) };
        report
    }

    /// Initialise `value` as this context's instance slot.
    ///
    /// # Safety
    ///
    /// `value` must be a zeroed (uninitialised) `GValue` the caller unsets.
    unsafe fn set_instance(&self, value: *mut wpe::GValue) {
        // SAFETY: init with its own registered type, THEN collect the instance
        // through that type's value table. Doing only the second half is the
        // silent-no-emission bug this comment exists to prevent.
        unsafe {
            wpe::g_value_init(value, self.gtype);
            wpe::g_value_set_instance(value, self.ctx.cast::<c_void>());
        }
    }

    /// Emit one signal that carries no arguments.
    fn emit_void(&self, signal_id: c_uint) {
        let mut instance = wpe::GValue::default();
        // SAFETY: the value is initialised, used, then unset.
        unsafe {
            self.set_instance(&mut instance);
            wpe::g_signal_emitv(&instance, signal_id, 0, core::ptr::null_mut());
            wpe::g_value_unset(&mut instance);
        }
    }

    /// Set the composition and tell WebKit to read it.
    ///
    /// `cursor_utf16` is an offset into `text` in UTF-16 code units, which
    /// is what `get_preedit` reports and what WebKit's `InputMethodFilter`
    /// clamps against `WTF::String::length()` before building the DOM
    /// composition's `EditingRange`. Callers holding an iced byte offset must
    /// convert with [`crate::input::utf16_caret`] - there is exactly one such
    /// boundary, [`crate::ffi::runtime::WebSession::ime_set_preedit`]. Emits `preedit-started` on the first composition
    /// and `preedit-changed` every time, which is the sequence WebKit's
    /// `InputMethodFilter` expects; a `preedit-changed` with no preceding
    /// `preedit-started` is silently ignored by it, so the ordering is
    /// load-bearing rather than cosmetic.
    ///
    /// One real WebKit behaviour to know about: `InputMethodFilter` compares
    /// the new preedit's UTF-8 against the one it holds and returns early
    /// when they are equal, so re-sending the same composition text with only a
    /// different caret offset is a no-op in the page. Measured, not assumed:
    /// re-emitting an identical composition produced no further
    /// `compositionupdate` in the native gate.
    pub fn set_preedit(&self, text: &str, cursor_utf16: u32) {
        let first = with_state(self.ctx, |s| {
            let was = s.preedit.is_some();
            s.preedit = Some((text.to_owned(), cursor_utf16));
            !was
        });
        if first {
            self.emit_void(self.signals.preedit_started);
        }
        self.emit_void(self.signals.preedit_changed);
    }

    /// End the composition without committing it (the IME cancelled).
    pub fn finish_preedit(&self) {
        let had = with_state(self.ctx, |s| s.preedit.take().is_some());
        // Tell WebKit the (now empty) composition, then that it finished, so the
        // page clears any on-the-spot text rather than leaving it rendered.
        self.emit_void(self.signals.preedit_changed);
        if had {
            self.emit_void(self.signals.preedit_finished);
        }
    }

    /// Commit `text` into the focused field.
    ///
    /// Any active composition is cleared first (a commit replaces it), matching
    /// iced's contract that an empty `Preedit` precedes every `Commit`.
    pub fn commit(&self, text: &str) {
        let c = match CString::new(text) {
            Ok(c) => c,
            // A NUL cannot be committed into a DOM value; refusing is correct.
            Err(_) => return,
        };
        let had = with_state(self.ctx, |s| s.preedit.take().is_some());
        let mut values = [wpe::GValue::default(), wpe::GValue::default()];
        // SAFETY: values[0] is the instance, values[1] the `const gchar*`
        // argument the `committed` signal declares. Both are unset afterwards.
        unsafe {
            self.set_instance(&mut values[0]);
            wpe::g_value_init(&mut values[1], g_type_string());
            wpe::g_value_set_string(&mut values[1], c.as_ptr());
            wpe::g_signal_emitv(
                values.as_ptr(),
                self.signals.committed,
                0,
                core::ptr::null_mut(),
            );
            wpe::g_value_unset(&mut values[0]);
            wpe::g_value_unset(&mut values[1]);
        }
        // Like GTK input methods, commit first and then end the preedit: an
        // empty preedit before the commit would end the composition with no
        // text, so `compositionend` would report empty data.
        if had {
            self.emit_void(self.signals.preedit_changed);
            self.emit_void(self.signals.preedit_finished);
        }
    }

    /// Ask the page to delete `n_chars` characters starting `offset`
    /// characters from the caret (negative offsets are before it) - the
    /// `delete-surrounding` contract.
    pub fn delete_surrounding(&self, offset: i32, n_chars: u32) {
        let mut values = [
            wpe::GValue::default(),
            wpe::GValue::default(),
            wpe::GValue::default(),
        ];
        // SAFETY: the signal declares `(int, guint)`; the array matches.
        unsafe {
            self.set_instance(&mut values[0]);
            wpe::g_value_init(&mut values[1], g_type_int());
            wpe::g_value_set_int(&mut values[1], offset as c_int);
            wpe::g_value_init(&mut values[2], g_type_uint());
            wpe::g_value_set_uint(&mut values[2], n_chars as c_uint);
            wpe::g_signal_emitv(
                values.as_ptr(),
                self.signals.delete_surrounding,
                0,
                core::ptr::null_mut(),
            );
            for v in &mut values {
                wpe::g_value_unset(v);
            }
        }
    }
}

impl Drop for ImeContext {
    fn drop(&mut self) {
        // Detach FIRST: WebKit must not be able to call a vfunc on an object
        // about to be released. This ordering is the whole no-UAF argument.
        // SAFETY: both pointers are still live here (the session drops this
        // before unref'ing its view).
        unsafe {
            wpe::webkit_web_view_set_input_method_context(self.web_view, core::ptr::null_mut());
        }
        let key = self.ctx as usize;
        STATE.with(|m| {
            m.borrow_mut().remove(&key);
        });
        // SAFETY: the construction reference.
        unsafe { wpe::g_object_unref(self.ctx.cast::<c_void>()) };
    }
}

// glib fundamental type ids. These are compile-time constants in the C headers
// (`G_TYPE_MAKE_FUNDAMENTAL(n)` = `n << 2`), not functions, so they are spelled
// out here rather than looked up.
//
// Source: `/usr/include/glib-2.0/gobject/gtype.h`
const fn g_type_int() -> wpe::GType {
    6 << 2
}
const fn g_type_uint() -> wpe::GType {
    7 << 2
}
const fn g_type_string() -> wpe::GType {
    16 << 2
}
