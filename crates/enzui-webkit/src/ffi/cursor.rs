//! The page's requested cursor, captured from the view class's cursor callback
//! so a widget can render it.
//!

use super::wpe;
use core::ffi::{CStr, c_char};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, OnceLock};

// The vtable patch writes the `set_cursor_from_name` slot by field access, so
// its byte offset in the mirrored `WPEViewClass` must equal the C layout's
// offset (168 on x86_64, pinned by a C `offsetof` probe against `WPEView.h`).
// If a future edit reorders the struct or a different arch changes GObjectClass
// size, this fails to compile rather than scribbling on the wrong vfunc slot.
const _: () = {
    assert!(
        core::mem::offset_of!(wpe::WPEViewClass, set_cursor_from_name) == 168,
        "WPEViewClass::set_cursor_from_name must be at offset 168 (x86_64); the \
         mirrored struct layout drifted from WPEView.h — re-run the C offsetof \
         probe and fix the struct before patching this vfunc"
    );
};

struct CursorObservation {
    name: String,
    revision: u64,
}

// Observations can be read across threads without accessing the native object.
static CURSOR_BY_VIEW: OnceLock<Mutex<HashMap<usize, CursorObservation>>> = OnceLock::new();

/// Class pointers already patched by this process.
static PATCHED_CLASSES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

/// Take a registry lock while recovering its contents after a panic.
///
/// These registries sit on `extern "C"` callback paths. A prior Rust panic must
/// not turn every later callback into another panic through mutex poisoning.
pub(super) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Run `patch` exactly once for `key`, with check, vtable transaction, and mark
/// in one process-wide critical section.
///
/// `patch` must perform the complete read-original/write-replacement operation.
/// Keeping it inside this helper is what prevents a second installer from
/// observing the replacement as though it were the original.
pub(super) fn patch_once(
    patched: &OnceLock<Mutex<HashSet<usize>>>,
    key: usize,
    patch: impl FnOnce(),
) -> bool {
    let mut keys = lock_unpoisoned(patched.get_or_init(|| Mutex::new(HashSet::new())));
    if keys.contains(&key) {
        return false;
    }
    patch();
    keys.insert(key);
    true
}

fn cursor_observations() -> &'static Mutex<HashMap<usize, CursorObservation>> {
    CURSOR_BY_VIEW.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The replacement `set_cursor_from_name` vfunc. Records the requested name
/// against the view that asked, then returns - the headless original was NULL,
/// so there is nothing to chain to (a non-headless view would need chaining;
/// required by the widget integration).
///
/// # Safety
///
/// Installed only as a `WPEViewClass::set_cursor_from_name` pointer, so WPE
/// calls it with a live `WPEView*` and either a valid C string or NULL.
extern "C" fn record_cursor(view: *mut wpe::WPEView, name: *const c_char) {
    let key = view as usize;
    let value = if name.is_null() {
        // A NULL name means "hide the cursor" in WPE; record it distinctly so a
        // caller can tell "hidden" from "never set".
        Cow::Borrowed("\u{0}hidden")
    } else {
        // SAFETY: WPE passes a valid NUL-terminated C string.
        unsafe { CStr::from_ptr(name) }.to_string_lossy()
    };
    let mut observations = lock_unpoisoned(cursor_observations());
    if let Some(observation) = observations.get_mut(&key) {
        if observation.name != value.as_ref() {
            observation.name = value.into_owned();
            observation.revision = observation.revision.wrapping_add(1);
        }
    } else {
        observations.insert(
            key,
            CursorObservation {
                name: value.into_owned(),
                revision: 1,
            },
        );
    }
}

/// Install the recorder on the concrete class of `view`, if not already
/// installed. Returns whether the vtable was patched (`true`) or was already
/// this code's (`false`) - the caller does not need this, but a test can assert the
/// first install actually replaced a different (NULL) pointer.
///
/// # Safety
///
/// `view` must be a live `WPEView*` whose instance-class pointer is valid to
/// read, and that concrete `WPEViewClass` and its mirrored vtable slot must be
/// valid and writable for the process lifetime. The caller must invoke this on
/// the main/engine thread required by the owning WPE runtime; this mutex only
/// coordinates enzUI's bookkeeping and does not make arbitrary off-thread
/// GObject access safe. The caller must also provide process-wide exclusivity
/// against any external code that patches `set_cursor_from_name` while or after
/// this recorder is installed. The headless original is NULL and is not
/// chained; if a platform supplies a non-NULL original, its lifetime must still
/// cover any external code that retained it before this replacement.
pub unsafe fn install_cursor_recorder(view: *mut wpe::WPEView) -> bool {
    // The class pointer is the first field of the GObject instance
    // (`GTypeInstance { GTypeClass *g_class; }`). Read it and treat it as the
    // WPEViewClass whose layout is mirrored here.
    // SAFETY: `view` is a live GObject-derived instance; its first pointer-sized
    // field is its class pointer.
    let class_ptr = unsafe { *(view as *const *mut wpe::WPEViewClass) };
    if class_ptr.is_null() {
        return false;
    }
    let class_key = class_ptr as usize;
    patch_once(&PATCHED_CLASSES, class_key, || {
        // SAFETY: `class_ptr` is the concrete `WPEViewClass` whose layout this code
        // mirror; this code overwrites exactly one vfunc slot whose C type matches the
        // callback. The enclosing critical section makes check/write/mark one
        // transaction among all enzUI installers in this process.
        unsafe {
            (*class_ptr).set_cursor_from_name = Some(record_cursor as wpe::SetCursorFromNameFn);
        }
    })
}

/// The cursor `view` most recently requested, or `None` if it never requested
/// one (or the recorder is not installed). A `"\0hidden"` sentinel is returned
/// verbatim for an explicit hide.
#[must_use]
pub fn last_cursor_for(view: *mut wpe::WPEView) -> Option<String> {
    let key = view as usize;
    lock_unpoisoned(cursor_observations())
        .get(&key)
        .map(|observation| observation.name.clone())
}

pub(super) fn cursor_revision_for(view: *mut wpe::WPEView) -> u64 {
    lock_unpoisoned(cursor_observations())
        .get(&(view as usize))
        .map_or(0, |observation| observation.revision)
}

/// Forget `view`'s recorded cursor. Called when a session drops so a reused
/// view pointer cannot read a dead session's cursor.
pub fn forget_view(view: *mut wpe::WPEView) {
    let key = view as usize;
    lock_unpoisoned(cursor_observations()).remove(&key);
}
