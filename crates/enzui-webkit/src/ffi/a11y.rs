//! Read the embedded page's accessibility tree over AT-SPI D-Bus.
//!
//! Headless WPE exposes an ATK socket in the UI process; the document tree
//! belongs to the sandboxed WebProcess. [`install_bind_recorder`] captures its
//! remote plug identifier while preserving native socket binding.
//! [`A11yBus`] reads owned roles, names, actions and bounds with finite deadlines.
//!
//! These facts implement [`crate::page_a11y::AccessibleSource`]. Publishing them
//! through a host toolkit's accessibility tree remains the adapter's responsibility.

use super::cursor::{lock_unpoisoned, patch_once};
use super::wpe;
use crate::deadline_source::{
    CompletionState, DeadlineRetirement, DeadlineSourceState, NativeSourceRemover, SourceRemover,
    retire_deadline,
};
use core::ffi::{c_char, c_int, c_uint, c_void};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

// The mirrored x86_64 interface must match WPEViewAccessible.h before vtable writes.
const _: () = {
    assert!(
        core::mem::offset_of!(wpe::WPEViewAccessibleInterface, bind) == 16,
        "WPEViewAccessibleInterface::bind must be at offset 16 (x86_64); the \
         mirrored struct drifted from WPEViewAccessible.h — re-run the C \
         offsetof probe before patching this vfunc"
    );
};

const G_BUS_TYPE_SESSION: c_int = 2;
// GDBus requires both AUTHENTICATION_CLIENT and MESSAGE_BUS_CONNECTION for named destinations.
const DBUS_CONN_FLAGS: c_int = 1 | (1 << 3);
const DBUS_TIMEOUT_MS: c_int = 5_000;

// A pending callback retains cleanup ownership after the bounded cancellation drain.
const DRAIN_CAP_MS: u64 = 2_000;

// The reply callback keeps this box alive until completion. After an expired
// cancellation drain, it also owns the loop, cancellable and a strong connection ref.
#[repr(C)]
struct DoActionState {
    main_loop: *mut wpe::GMainLoop,
    conn: *mut c_void,
    cancellable: *mut c_void,
    reply: *mut c_void,
    error: Option<String>,
    callback_fired: bool,
    // GLib can dispatch the deadline and reply together; retirement needs both facts.
    deadline_fired: bool,
    abandoned: bool,
}

thread_local! {
    static ABANDONED_CLEANUPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Number of cancelled action callbacks that completed deferred cleanup on this thread.
#[must_use]
pub fn abandoned_cleanup_count() -> u64 {
    ABANDONED_CLEANUPS.with(std::cell::Cell::get)
}

// Safety: ptr is the unique live, abandoned state box on its owning thread.
unsafe fn free_abandoned_do_action(ptr: *mut DoActionState) {
    // SAFETY: `ptr` came from `Box::into_raw`; recover and free it. Every GLib
    // object it names was kept alive precisely for this moment.
    let boxed = unsafe { Box::from_raw(ptr) };
    unsafe {
        if !boxed.reply.is_null() {
            wpe::g_variant_unref(boxed.reply);
        }
        wpe::g_main_loop_unref(boxed.main_loop);
        wpe::g_object_unref(boxed.cancellable);
        wpe::g_object_unref(boxed.conn);
    }
    ABANDONED_CLEANUPS.with(|c| c.set(c.get() + 1));
}

// GAsyncReadyCallback receives the original owner-thread state box as user_data.
extern "C" fn on_do_action_ready(
    _source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    // SAFETY: `user_data` is the `DoActionState` box passed to the call.
    let state = unsafe { &mut *user_data.cast::<DoActionState>() };
    mark_do_action_completion(state);
    let mut err: *mut wpe::GError = core::ptr::null_mut();
    // SAFETY: completing its own outstanding call.
    let reply = unsafe { wpe::g_dbus_connection_call_finish(state.conn, result, &mut err) };
    if reply.is_null() {
        // SAFETY: the call failed, so `err` is set and owned here.
        state.error = Some(unsafe { take_gerror(err) });
    } else {
        state.reply = reply;
    }
    // Idempotent, so racing the deadline is harmless.
    // SAFETY: the loop, still alive (the caller unrefs it after this returns, or
    // this code frees it itself just below on the abandoned path).
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
    // if the main thread already gave up waiting, it
    // handed over ownership. Free everything it deliberately did not, and record
    // that this happened. After this the box is gone, so nothing else may read
    // `state`.
    if state.abandoned {
        // SAFETY: this code owns the abandoned box; single-threaded, no other reader.
        unsafe { free_abandoned_do_action(user_data.cast::<DoActionState>()) };
    }
}

// Split from each callback's GLib quit so a dispatch-order test can drive both
// with no main context.
fn mark_do_action_completion(state: &mut DoActionState) {
    state.callback_fired = true;
}

fn mark_do_action_deadline(state: &mut DoActionState) -> wpe::GBoolean {
    state.deadline_fired = true;
    wpe::G_FALSE // G_SOURCE_REMOVE: the source destroys itself.
}

fn retire_do_action_deadline<R>(
    state: &DoActionState,
    deadline_tag: c_uint,
    remover: &mut R,
) -> DeadlineRetirement
where
    R: SourceRemover + ?Sized,
{
    retire_deadline(
        CompletionState::from_resolved(state.callback_fired),
        DeadlineSourceState::from_fired(state.deadline_fired),
        deadline_tag,
        remover,
    )
}

/// The deadline `GSourceFunc` for a `DoAction` loop.
///
/// Touches nothing beyond the flag and the loop: the reply callback may still
/// be outstanding, and the caller's cancel/drain path owns the cleanup.
///
/// # Safety
///
/// Installed only by the `g_timeout_add` above with the same box.
extern "C" fn on_do_action_deadline(user_data: *mut c_void) -> wpe::GBoolean {
    if user_data.is_null() {
        return wpe::G_FALSE;
    }
    // SAFETY: `user_data` is the live `DoActionState` box.
    let state = unsafe { &mut *user_data.cast::<DoActionState>() };
    let disposition = mark_do_action_deadline(state);
    // SAFETY: the loop; quit is idempotent so racing the reply is safe.
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
    disposition
}

/// Maximum UTF-8 bytes retained from any one native accessibility string.
///
/// This applies uniformly to accessible names, action names, bus names, object
/// paths, plug ids, and the accessibility-bus address. Native lengths are
/// checked before a Rust string is allocated. Sixteen KiB is deliberately far
/// above ordinary AT-SPI labels and routing identities while preventing a page
/// from making one ARIA label a multi-megabyte UI-process allocation.
pub const MAX_A11Y_STRING_BYTES: usize = 16 * 1024;

/// Maximum native string bytes copied during one accessibility-tree walk.
///
/// The budget is shared by root and child routing identities, accessible names,
/// and action names. It counts every accepted native string before copying it,
/// including an identity later discarded because that child vanished. Thus the
/// sum of page-controlled string allocations made by a walk cannot cross this
/// ceiling. A walk refuses with [`A11yError::WalkStringBudgetExceeded`] rather
/// than publishing a partial tree as complete.
pub const MAX_A11Y_WALK_STRING_BYTES: usize = 256 * 1024;

/// A retained native string's purpose. Routing identities have distinct kinds
/// so callers can distinguish a refused address from display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A11yStringKind {
    /// A node's human-facing accessible name.
    AccessibleName,
    /// An action's machine-readable name.
    ActionName,
    /// An AT-SPI D-Bus destination name.
    BusName,
    /// An AT-SPI object path.
    ObjectPath,
    /// The combined bus/path identifier delivered by WPE's `bind` callback.
    PlugId,
    /// The address returned by the accessibility bus broker.
    A11yBusAddress,
}

/// The shared byte account for one tree walk. Checks happen before copying.
#[derive(Debug)]
struct WalkStringBudget {
    retained: usize,
    ceiling: usize,
}

impl WalkStringBudget {
    fn new(ceiling: usize) -> Self {
        Self {
            retained: 0,
            ceiling,
        }
    }

    fn reserve(&mut self, kind: A11yStringKind, bytes: usize) -> Result<(), A11yError> {
        if bytes > MAX_A11Y_STRING_BYTES {
            return Err(A11yError::NativeStringTooLong {
                kind,
                bytes,
                max_bytes: MAX_A11Y_STRING_BYTES,
            });
        }
        let Some(next) = self.retained.checked_add(bytes) else {
            return Err(A11yError::WalkStringBudgetExceeded {
                kind,
                bytes,
                retained_bytes: self.retained,
                max_bytes: self.ceiling,
            });
        };
        if next > self.ceiling {
            return Err(A11yError::WalkStringBudgetExceeded {
                kind,
                bytes,
                retained_bytes: self.retained,
                max_bytes: self.ceiling,
            });
        }
        self.retained = next;
        Ok(())
    }

    fn copy_rust_string(&mut self, value: &str, kind: A11yStringKind) -> Result<String, A11yError> {
        self.reserve(kind, value.len())?;
        Ok(value.to_owned())
    }
}

/// Copy a GVariant string only after its native-reported byte length passes the
/// per-string and current walk limits.
///
/// # Safety
///
/// `variant` must be a live string-like `GVariant` for the duration of this
/// call. `g_variant_get_string` guarantees the returned bytes remain valid
/// while that variant is live.
unsafe fn copy_variant_string(
    variant: *mut c_void,
    kind: A11yStringKind,
    budget: &mut WalkStringBudget,
) -> Result<String, A11yError> {
    let mut bytes = 0usize;
    // SAFETY: the caller supplies a live string-like variant and an initialized
    // length out-parameter.
    let ptr = unsafe { wpe::g_variant_get_string(variant, &mut bytes) };
    if ptr.is_null() {
        return Err(A11yError::UnexpectedReply(
            "native string variant returned NULL".into(),
        ));
    }
    // Reject from the native-reported length before even traversing the bytes,
    // then inspect UTF-8 without allocating before `to_owned` copies.
    budget.reserve(kind, bytes)?;
    // SAFETY: GLib reports exactly `bytes` readable bytes before the trailing
    // NUL, all borrowed from the still-live variant.
    let raw = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), bytes) };
    let value = core::str::from_utf8(raw).map_err(|_| {
        A11yError::UnexpectedReply("native string variant was not valid UTF-8".into())
    })?;
    Ok(value.to_owned())
}

/// Cap on actions read per node. `NActions` is page-supplied, so a hostile page
/// could report a huge count and turn one node into thousands of D-Bus round
/// trips. AT only ever uses the first (by AT-SPI convention the default action),
/// so a small cap loses nothing real.
const MAX_ACTIONS_PER_NODE: i32 = 8;

/// Hard ceiling on the children read from one node, whatever the walk's
/// remaining node budget is.
///
/// `GetChildren` returns a page-controlled arity. Unclamped, a node claiming
/// millions of children would reserve memory and spend D-Bus round trips before
/// the walk's global node budget could stop it. The ceiling exists so the per-node cost is
/// bounded on its own terms; a real page's widest node (a long list, a big
/// table row set) is far under it.
const MAX_CHILDREN_PER_NODE: usize = 256;

/// The per-node child arity ceiling, tied coherently to the walk's remaining
/// node budget.
///
/// A walk with `budget_left` nodes to spend can never keep more than
/// `budget_left` children of this node, so fetching more is pure waste, and
/// `MAX_CHILDREN_PER_NODE` caps the case where the budget itself is large.
/// Deriving the cap from the live budget rather than from a second independent
/// constant is what keeps the two bounds coherent: raising `max_nodes` cannot
/// silently uncap a single node beyond the hard ceiling, and lowering it tightens
/// the per-node work immediately.
fn child_arity_cap(budget_left: usize) -> usize {
    budget_left.min(MAX_CHILDREN_PER_NODE)
}

/// What one `GetChildren` read yielded: the children actually read, and whether
/// the page reported more than the cap allowed.
///
/// `truncated` is carried rather than dropped so the walk can say "this subtree
/// is incomplete" instead of publishing a clamped list as if it were the whole
/// tree.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ChildList {
    children: Vec<(String, String)>,
    truncated: bool,
}

/// The `a(so)` array `GetChildren` returns, as the clamp sees it.
///
/// A trait (rather than the raw `GVariant*`) so the clamp itself can be driven
/// by a stub reporting an arity no real bus would produce: the defect is about
/// *trusting the reported count*, and only an injectable count can prove the
/// count is no longer trusted. The real implementation is the thin FFI one
/// below.
trait ChildArray {
    /// The arity the page reported. Untrusted by construction.
    fn reported_len(&self) -> usize;
    /// Read entry `i`, or `None` if it is not the `(so)` pair this code accepts.
    /// Native strings are charged to `budget` before either is copied.
    fn entry(
        &self,
        i: usize,
        budget: &mut WalkStringBudget,
    ) -> Result<Option<(String, String)>, A11yError>;
}

/// Clamp first, then allocate, then fetch - in that order.
///
/// The order is the whole fix: `Vec::with_capacity(reported)` commits ~48 bytes
/// per claimed child before a single entry is read, and the fetch loop then
/// performs `reported` reads. Both are bounded to `cap` here, and a clamp that
/// dropped anything is reported instead of hidden.
fn read_children_capped<A: ChildArray + ?Sized>(
    array: &A,
    cap: usize,
    budget: &mut WalkStringBudget,
) -> Result<ChildList, A11yError> {
    let reported = array.reported_len();
    let take = reported.min(cap);
    let mut children = Vec::with_capacity(take);
    for i in 0..take {
        if let Some(entry) = array.entry(i, budget)? {
            children.push(entry);
        }
    }
    Ok(ChildList {
        children,
        truncated: take < reported,
    })
}

/// The real `a(so)` array, read through `g_variant_*`.
///
/// Borrows the array variant; the caller owns and unrefs it.
struct VariantChildArray {
    array: *mut c_void,
}

impl ChildArray for VariantChildArray {
    fn reported_len(&self) -> usize {
        // SAFETY: `array` is a live owned array variant held by the caller.
        unsafe { wpe::g_variant_n_children(self.array) }
    }

    fn entry(
        &self,
        i: usize,
        budget: &mut WalkStringBudget,
    ) -> Result<Option<(String, String)>, A11yError> {
        // SAFETY: `i` is below the arity just read; every intermediate variant
        // is unref'd on both the accept and the reject path.
        unsafe {
            let entry = wpe::g_variant_get_child_value(self.array, i);
            let out = if wpe::g_variant_n_children(entry) == 2 {
                let vb = wpe::g_variant_get_child_value(entry, 0);
                let vp = wpe::g_variant_get_child_value(entry, 1);
                let bus = copy_variant_string(vb, A11yStringKind::BusName, budget);
                let path = match bus {
                    Ok(bus) => copy_variant_string(vp, A11yStringKind::ObjectPath, budget)
                        .map(|path| Some((bus, path))),
                    Err(error) => Err(error),
                };
                wpe::g_variant_unref(vb);
                wpe::g_variant_unref(vp);
                path
            } else {
                Ok(None)
            };
            wpe::g_variant_unref(entry);
            out
        }
    }
}

/// The callback's combined plug id is itself one retained native string, so it
/// uses the same ceiling as every other native string.
const MAX_PLUG_ID_BYTES: usize = MAX_A11Y_STRING_BYTES;

/// Plug ids captured from `bind`, keyed by the accessible object pointer.
/// Process-wide so a host reader can observe a callback delivered on another
/// WPE thread without pretending the GObject itself is safe to move. Refusals
/// are retained too, so an oversized routing identity is surfaced by the next
/// tree request instead of becoming an indistinguishable `NotBound`.
static PLUG_BY_ACCESSIBLE: OnceLock<Mutex<HashMap<usize, Result<String, A11yError>>>> =
    OnceLock::new();

/// Interface vtables already patched, keyed by vtable pointer (not by comparing
/// function pointers, which Rust warns are not uniquely addressable).
static PATCHED_IFACES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

/// The original `bind` keyed by the exact interface-vtable address on which its
/// replacement was installed. This remains keyed: two accessible classes can
/// have different originals, and an arbitrary map value embeds the wrong
/// socket.
static ORIGINAL_BIND: OnceLock<Mutex<HashMap<usize, wpe::AccessibleBindFn>>> = OnceLock::new();

fn plug_observations() -> &'static Mutex<HashMap<usize, Result<String, A11yError>>> {
    PLUG_BY_ACCESSIBLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn original_binds() -> &'static Mutex<HashMap<usize, wpe::AccessibleBindFn>> {
    ORIGINAL_BIND.get_or_init(|| Mutex::new(HashMap::new()))
}

thread_local! {
    /// Chain attempts that found no original callback for a derived key. A
    /// missing original is a defect in the install/dispatch pairing, so it is
    /// recorded (and shouted on stderr) rather than skipped in silence. Bounded
    /// by [`MAX_RECORDED_MISSING_CHAINS`]: stderr stays loud past the bound, so
    /// a repeating failure cannot grow this without limit.
    static MISSING_CHAINS: RefCell<Vec<ChainTarget>> = const { RefCell::new(Vec::new()) };

    /// How many times [`interface_key`] ran. Installation and dispatch must
    /// share that one derivation, and this makes "shared" observable instead of
    /// a claim about the source text.
    static KEY_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many missing-chain events are kept in memory. Every one is also printed
/// to stderr, so the bound trims the retained list, not the loudness.
const MAX_RECORDED_MISSING_CHAINS: usize = 64;

/// What a chain lookup resolved to. Every non-callback outcome is an explicit,
/// named state: "no original ran" must never be indistinguishable from "the
/// original ran".
#[derive(Clone, Copy)]
enum ChainTarget {
    /// The original `bind` recorded for this exact interface vtable.
    Original(wpe::AccessibleBindFn),
    /// No `WPEViewAccessible` interface key could be derived from the instance
    /// (NULL instance, NULL class, or the class does not implement it).
    NoInterfaceKey,
    /// A key was derived, but nothing was recorded for it - the replacement is
    /// installed on a vtable whose original was never captured.
    MissingOriginal(usize),
}

impl core::fmt::Debug for ChainTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Original(_) => write!(f, "Original(<bind fn>)"),
            Self::NoInterfaceKey => write!(f, "NoInterfaceKey"),
            Self::MissingOriginal(k) => write!(f, "MissingOriginal({k:#x})"),
        }
    }
}

/// The one derivation of a `WPEViewAccessible` interface-vtable key from a
/// concrete accessible instance, shared by installation and dispatch.
///
/// The key IS the interface vtable address, so the caller that needs to write
/// the vtable casts it back rather than peeking a second time. Two paths that
/// derived the key separately could drift apart; one that cannot.
///
/// Returns `None` when `accessible` is null or there is no such interface
/// to key on.
///
/// # Safety
///
/// - If `accessible` is non-null it must point to a live GObject-derived
///   instance whose first pointer-sized field is a valid class pointer
///   (the GObject instance layout invariant).
/// - The class pointer must outlive this call and the interface vtable
///   reachable through `g_type_interface_peek` must be valid to read.
/// - Must be called from the GLib main/engine thread.
unsafe fn interface_key(accessible: *mut wpe::WPEViewAccessible) -> Option<usize> {
    KEY_DERIVATIONS.with(|c| c.set(c.get().saturating_add(1)));
    if accessible.is_null() {
        return None;
    }
    // SAFETY: GObject ABI places the class pointer at offset 0 of every
    // instance; the caller guarantees `accessible` is a live instance.
    let instance_class = unsafe { *(accessible as *const *mut c_void) };
    if instance_class.is_null() {
        return None;
    }
    // SAFETY: looking up an interface vtable on an initialised class; peek
    // takes no reference and returns NULL if unimplemented.
    let iface =
        unsafe { wpe::g_type_interface_peek(instance_class, wpe::wpe_view_accessible_get_type()) };
    if iface.is_null() {
        return None;
    }
    Some(iface as usize)
}

/// Resolve the original `bind` for a derived key.
///
/// Keyed, never "whichever entry the hash map yields first": with more than one
/// accessible class that arbitrary pick embeds another class's socket.
fn chain_target(key: Option<usize>) -> ChainTarget {
    let Some(key) = key else {
        return ChainTarget::NoInterfaceKey;
    };
    // Copy the function pointer while protected, then drop the guard before
    // `chain_bind` calls foreign code. The original may re-enter this module.
    let original = {
        let originals = lock_unpoisoned(original_binds());
        originals.get(&key).copied()
    };
    original.map_or(ChainTarget::MissingOriginal(key), ChainTarget::Original)
}

/// Chain to the original `bind` for `key` - it does the `AtkSocket` embed.
/// Skipping it would break the mechanism this code is observing, so a missing
/// original is recorded and shouted, not swallowed.
fn chain_bind(key: Option<usize>, accessible: *mut wpe::WPEViewAccessible, plug_id: *const c_char) {
    match chain_target(key) {
        ChainTarget::Original(f) => f(accessible, plug_id),
        missing => {
            eprintln!("enzui-webkit: a11y bind chaining found no original callback: {missing:?}");
            MISSING_CHAINS.with(|m| {
                let mut recorded = m.borrow_mut();
                if recorded.len() < MAX_RECORDED_MISSING_CHAINS {
                    recorded.push(missing);
                }
            });
        }
    }
}

/// The replacement `bind` vfunc: record the plug id, then call the original so
/// the real embedding still happens.
///
/// # Safety
///
/// Installed only as a `WPEViewAccessibleInterface::bind` pointer, so WPE calls
/// it with a live accessible and a valid C string (or NULL).
extern "C" fn record_bind(accessible: *mut wpe::WPEViewAccessible, plug_id: *const c_char) {
    if plug_id.is_null() {
        // A NULL bind withdraws the publication. Do not let an earlier valid id
        // or refusal leak into this new unbound state.
        forget_accessible(accessible);
    } else {
        // SAFETY: WPE passes a NUL-terminated C string. The bounded scan stops
        // after `MAX_PLUG_ID_BYTES + 1` observations even if it is oversized.
        let observed = unsafe { copy_bounded_plug_id(plug_id) };
        record_plug_id(accessible, observed);
    }
    // Dispatch through the SAME key derivation installation used, so the
    // original retrieved is this instance's class's own.
    // SAFETY: WPE called this vfunc with a live `WPEViewAccessible*`
    // whose GObject class pointer and interface vtable are valid for the
    // duration of the callback.
    chain_bind(unsafe { interface_key(accessible) }, accessible, plug_id);
}

/// Copy a callback-owned plug id after a bounded NUL search.
///
/// # Safety
///
/// `plug_id` must point to WPE's valid NUL-terminated callback string.
unsafe fn copy_bounded_plug_id(plug_id: *const c_char) -> Result<String, A11yError> {
    for bytes in 0..=MAX_PLUG_ID_BYTES {
        // SAFETY: the caller guarantees a NUL-terminated string, so every byte
        // through the first NUL is readable; this loop never scans beyond its
        // own explicit cap.
        if unsafe { *plug_id.add(bytes) } == 0 {
            // SAFETY: the scan just established `bytes` readable non-NUL bytes.
            let raw = unsafe { core::slice::from_raw_parts(plug_id.cast::<u8>(), bytes) };
            let value = core::str::from_utf8(raw).map_err(|_| {
                A11yError::UnexpectedReply("WPE accessibility plug id was not UTF-8".into())
            })?;
            return Ok(value.to_owned());
        }
    }
    Err(A11yError::NativeStringTooLong {
        kind: A11yStringKind::PlugId,
        bytes: MAX_PLUG_ID_BYTES + 1,
        max_bytes: MAX_PLUG_ID_BYTES,
    })
}

fn record_plug_id(accessible: *mut wpe::WPEViewAccessible, id: Result<String, A11yError>) {
    lock_unpoisoned(plug_observations()).insert(accessible as usize, id);
}

/// Errors from the accessibility bridge. Every one is a loud, typed refusal -
/// none of them degrade to "no accessibility, carry on quietly".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A11yError {
    /// `wpe_view_get_accessible` returned NULL - the platform has no a11y
    /// implementation at all.
    NoAccessible,
    /// The concrete accessible does not implement the `WPEViewAccessible`
    /// interface, so there is no `bind` vfunc to observe.
    NoInterface,
    /// The WebProcess never called `bind`, so no remote tree was ever
    /// published. Distinct from "the tree is empty".
    NotBound,
    /// The plug id was not `<dbus-name>:<object-path>`.
    MalformedPlugId(String),
    /// Could not reach the AT-SPI bus (address lookup or connection failed).
    NoA11yBus(String),
    /// An AT-SPI D-Bus call failed.
    DbusCall(String),
    /// A native string exceeded the per-string ceiling. The native-reported
    /// length was checked before any Rust allocation or copy.
    NativeStringTooLong {
        /// What the refused string would have represented.
        kind: A11yStringKind,
        /// Native-reported bytes (or the bounded observed prefix for a C string).
        bytes: usize,
        /// The per-string ceiling.
        max_bytes: usize,
    },
    /// One individually valid string would make a walk cross its cumulative
    /// native-string ceiling. No bytes from the refused string were copied.
    WalkStringBudgetExceeded {
        /// What the refused string would have represented.
        kind: A11yStringKind,
        /// Bytes requested by this string.
        bytes: usize,
        /// Bytes already accepted by this walk.
        retained_bytes: usize,
        /// The walk ceiling.
        max_bytes: usize,
    },
    /// A reply had a shape this code does not accept (wrong arity/type).
    UnexpectedReply(String),
}

impl A11yError {
    fn is_string_budget_refusal(&self) -> bool {
        matches!(
            self,
            Self::NativeStringTooLong { .. } | Self::WalkStringBudgetExceeded { .. }
        )
    }
}

impl core::fmt::Display for A11yError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoAccessible => write!(f, "wpe_view_get_accessible returned NULL"),
            Self::NoInterface => write!(f, "the accessible does not implement WPEViewAccessible"),
            Self::NotBound => write!(
                f,
                "the WebProcess never called bind(); no accessible tree was published"
            ),
            Self::MalformedPlugId(s) => write!(f, "malformed plug id: {s}"),
            Self::NoA11yBus(s) => write!(f, "AT-SPI bus unreachable: {s}"),
            Self::DbusCall(s) => write!(f, "AT-SPI call failed: {s}"),
            Self::NativeStringTooLong {
                kind,
                bytes,
                max_bytes,
            } => write!(
                f,
                "native accessibility {kind:?} string is {bytes} bytes; limit is {max_bytes}"
            ),
            Self::WalkStringBudgetExceeded {
                kind,
                bytes,
                retained_bytes,
                max_bytes,
            } => write!(
                f,
                "native accessibility walk string budget exceeded by {kind:?}: \
                 {retained_bytes} bytes retained, {bytes} requested, limit is {max_bytes}"
            ),
            Self::UnexpectedReply(s) => write!(f, "unexpected AT-SPI reply: {s}"),
        }
    }
}

/// A node in the page's accessible tree, as read across the process seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A11yNode {
    /// The AT-SPI role number (see [`role`] constants).
    pub role: u32,
    /// The accessible name - for a document this is the page `<title>`; for a
    /// button or link it is its label.
    pub name: String,
    /// Children, recursively (bounded by the walk's depth/count caps and by the
    /// per-node arity ceiling, `child_arity_cap`).
    pub children: Vec<A11yNode>,
    /// The page reported children this walk did not read: the per-node
    /// arity ceiling or the walk's remaining node budget stopped it.
    ///
    /// Carried per node rather than only globally so a diagnostic can name
    /// *where* the tree is incomplete. A clamped node reported as complete is
    /// the failure mode this exists to prevent - an AT client would conclude the
    /// page has exactly the children it can see.
    pub children_truncated: bool,
    /// The bus name that published this node. Kept so an AT
    /// action can be sent back to this exact object: without the address a
    /// tree is readable and inert.
    pub bus_name: String,
    /// This node's AT-SPI object path.
    pub path: String,
    /// The node's machine-readable action names, in index order.
    ///
    /// Read with `Action.GetName(i)`, deliberately not `Action.GetActions`:
    /// `GetActions` returns *localized* names ("Cliquer"), and matching an
    /// English allow-list against a localized string would make page controls
    /// operable only in an English locale. `GetName` is documented as the
    /// machine-readable name, which is what
    /// [`ACTIVATION_ACTIONS`](crate::page_a11y::ACTIVATION_ACTIONS) matches.
    pub actions: Vec<String>,
}

impl A11yNode {
    /// Depth-first search for the first descendant (or self) with `role`.
    #[must_use]
    pub fn find_by_role(&self, role: u32) -> Option<&A11yNode> {
        if self.role == role {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find_by_role(role))
    }

    /// Every (role, name) pair in the subtree, depth-first. Used by the gate to
    /// assert the page's elements arrived with the right roles AND names.
    #[must_use]
    pub fn flatten(&self) -> Vec<(u32, String)> {
        let mut out = vec![(self.role, self.name.clone())];
        for c in &self.children {
            out.extend(c.flatten());
        }
        out
    }

    /// Total node count in the subtree.
    #[must_use]
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(A11yNode::count).sum::<usize>()
    }

    /// Whether any node in the subtree had children dropped by the arity
    /// ceiling or the node budget.
    ///
    /// The honest headline for a walk: `false` means what was read is the whole
    /// tree, `true` means it is a prefix of it.
    #[must_use]
    pub fn subtree_truncated(&self) -> bool {
        self.children_truncated || self.children.iter().any(A11yNode::subtree_truncated)
    }

    /// Every truncated node's object path, depth-first - the diagnostic that
    /// says *where* the tree stops being complete rather than merely that it
    /// does.
    #[must_use]
    pub fn truncated_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.children_truncated {
            out.push(self.path.clone());
        }
        for c in &self.children {
            out.extend(c.truncated_paths());
        }
        out
    }
}

/// The seam between the AT-SPI facts read here and the toolkit semantics the
/// widget publishes. The translation itself is pure and lives
/// in [`crate::page_a11y`], so it compiles and tests feature-off; this impl is
/// the only feature-on part of it.
impl crate::page_a11y::AccessibleSource for A11yNode {
    fn atspi_role(&self) -> u32 {
        self.role
    }
    fn accessible_name(&self) -> &str {
        &self.name
    }
    fn accessible_children(&self) -> &[Self] {
        &self.children
    }
    fn accessible_address(&self) -> Option<crate::page_a11y::PageNodeAddress> {
        // A walked node always has an address; an empty one would be a bug in
        // the walk rather than a node that cannot be addressed, so report the
        // absence instead of handing out an address that resolves to nothing.
        (!self.bus_name.is_empty() && !self.path.is_empty()).then(|| {
            crate::page_a11y::PageNodeAddress::native(self.bus_name.clone(), self.path.clone())
        })
    }
    fn accessible_actions(&self) -> &[String] {
        &self.actions
    }
}

/// AT-SPI role numbers, taken from `/usr/include/at-spi-2.0/atspi/atspi-constants.h`
/// (`AtspiRole`) and confirmed against a real walk of a real page.
pub mod role {
    /// `ATSPI_ROLE_FILLER` - the WPE socket node itself.
    pub const FILLER: u32 = 20;
    /// `ATSPI_ROLE_SCROLL_PANE` - WebKit's frame node.
    pub const SCROLL_PANE: u32 = 49;
    /// `ATSPI_ROLE_PUSH_BUTTON` - a `<button>`.
    pub const PUSH_BUTTON: u32 = 43;
    /// `ATSPI_ROLE_HEADING` - an `<h1>`…`<h6>`.
    pub const HEADING: u32 = 83;
    /// `ATSPI_ROLE_SECTION` - a generic grouping element.
    pub const SECTION: u32 = 85;
    /// `ATSPI_ROLE_LINK` - an `<a href>`.
    pub const LINK: u32 = 88;
    /// `ATSPI_ROLE_DOCUMENT_WEB` - the page document; its accessible name
    /// is the `<title>`.
    pub const DOCUMENT_WEB: u32 = 95;
    /// `ATSPI_ROLE_ENTRY` - a text `<input>`.
    pub const ENTRY: u32 = 79;
    /// `ATSPI_ROLE_STATIC` - non-interactive text.
    pub const STATIC: u32 = 116;
}

/// Install the plug-id recorder on `accessible`'s interface vtable.
///
/// Returns `true` if this call installed it, `false` if it was already there.
///
/// # Safety
///
/// `accessible` must be a live `WPEViewAccessible*` whose instance-class
/// pointer and implemented `WPEViewAccessibleInterface` are valid to inspect;
/// the mirrored interface vtable and its `bind` slot must remain valid and
/// writable for the process lifetime. This must run on the main/engine thread
/// required by the owning WPE runtime: the registry mutex coordinates enzUI's
/// process-wide patch transaction, but does not make arbitrary off-thread
/// GObject access safe. The caller must provide process-wide exclusivity from
/// external vtable patchers while and after the recorder is installed. The
/// original `bind` captured here must remain callable for as long as the
/// replacement can be invoked, because every callback chains to that exact
/// interface's original after releasing the registry lock.
pub unsafe fn install_bind_recorder(accessible: *mut wpe::WPEViewAccessible) -> bool {
    // The same derivation `record_bind` dispatches through: the key recorded
    // here is exactly the key looked up there.
    // SAFETY: the caller guarantees `accessible` is a live
    // `WPEViewAccessible*` with a valid instance-class pointer and
    // interface vtable, called from the main/engine thread.
    let Some(key) = (unsafe { interface_key(accessible) }) else {
        return false;
    };
    let iface = key as *mut wpe::WPEViewAccessibleInterface;
    patch_once(&PATCHED_IFACES, key, || {
        // SAFETY: `iface` is the WPEViewAccessible vtable whose layout this code
        // mirror; this code reads and replace exactly one vfunc with the matching C
        // type. Capture, write, and patched-mark are one process-wide
        // transaction, so another enzUI installer cannot capture the recorder
        // as its "original".
        unsafe {
            if let Some(orig) = (*iface).bind {
                lock_unpoisoned(original_binds()).insert(key, orig);
            }
            (*iface).bind = Some(record_bind as wpe::AccessibleBindFn);
        }
    })
}

/// The bounded AT-SPI plug-id observation for `accessible`.
///
/// The outer `Option` distinguishes "no current publication" from a callback;
/// the inner `Result` distinguishes a usable identity from its typed refusal.
/// Both states are cloned under one lock, so a rebind cannot race two separate
/// success/error lookups into a stale combination.
#[must_use]
pub fn plug_id_result_for(
    accessible: *mut wpe::WPEViewAccessible,
) -> Option<Result<String, A11yError>> {
    lock_unpoisoned(plug_observations())
        .get(&(accessible as usize))
        .cloned()
}

/// The bounded AT-SPI plug id the WebProcess published for `accessible`.
///
/// `None` means either no tree has been published yet or the native identity
/// was refused; callers that need the distinction use [`plug_id_result_for`].
#[must_use]
pub fn plug_id_for(accessible: *mut wpe::WPEViewAccessible) -> Option<String> {
    plug_id_result_for(accessible).and_then(Result::ok)
}

/// Forget a dropped session's plug id.
pub fn forget_accessible(accessible: *mut wpe::WPEViewAccessible) {
    lock_unpoisoned(plug_observations()).remove(&(accessible as usize));
}

/// Split a plug id `"<dbus-name>:<object-path>"` into its two halves.
///
/// The D-Bus name itself contains `.` and `-` but never `/`, and the object
/// path always starts `/`, so the split point is the `:` immediately before the
/// first `/`. A plain `find(':')` would be wrong - the name can contain a colon
/// (`:1.42` unique names), which is why this is a named, unit-tested function
/// rather than an inline expression.
///
/// # Errors
///
/// [`A11yError::MalformedPlugId`] if there is no `/`, or no `:` before it;
/// [`A11yError::NativeStringTooLong`] if the retained native identity exceeds
/// [`MAX_A11Y_STRING_BYTES`].
pub fn split_plug_id(plug: &str) -> Result<(String, String), A11yError> {
    if plug.len() > MAX_PLUG_ID_BYTES {
        return Err(A11yError::NativeStringTooLong {
            kind: A11yStringKind::PlugId,
            bytes: plug.len(),
            max_bytes: MAX_PLUG_ID_BYTES,
        });
    }
    let slash = plug
        .find('/')
        .ok_or_else(|| A11yError::MalformedPlugId(plug.to_string()))?;
    if slash == 0 {
        return Err(A11yError::MalformedPlugId(plug.to_string()));
    }
    let before = &plug[..slash];
    if !before.ends_with(':') {
        return Err(A11yError::MalformedPlugId(plug.to_string()));
    }
    let name = &before[..before.len() - 1];
    if name.is_empty() {
        return Err(A11yError::MalformedPlugId(plug.to_string()));
    }
    let path = &plug[slash..];
    if name.len() > MAX_A11Y_STRING_BYTES {
        return Err(A11yError::NativeStringTooLong {
            kind: A11yStringKind::BusName,
            bytes: name.len(),
            max_bytes: MAX_A11Y_STRING_BYTES,
        });
    }
    if path.len() > MAX_A11Y_STRING_BYTES {
        return Err(A11yError::NativeStringTooLong {
            kind: A11yStringKind::ObjectPath,
            bytes: path.len(),
            max_bytes: MAX_A11Y_STRING_BYTES,
        });
    }
    Ok((name.to_string(), path.to_string()))
}

// ---------------------------------------------------------------------------
// The AT-SPI D-Bus client.
// ---------------------------------------------------------------------------

/// Owns a `GDBusConnection` to the AT-SPI bus and unrefs it on drop.
pub struct A11yBus {
    conn: *mut c_void,
}

impl Drop for A11yBus {
    fn drop(&mut self) {
        if !self.conn.is_null() {
            // SAFETY: `conn` is an owned GDBusConnection.
            unsafe { wpe::g_object_unref(self.conn) };
        }
    }
}

/// Read the message from a `GError` and free it, or return a placeholder
/// if `err` is null.
///
/// # Safety
///
/// - If `err` is non-null it must point to a live, validly-initialized
///   `GError` whose `message` field is a valid NUL-terminated C string
///   (as guaranteed by `g_error_new` and related GLib constructors).
/// - The caller must own the `GError`: this function frees it with
///   `g_error_free` exactly once, so the pointer must not be used
///   afterwards and must not have been freed already.
/// - Must be called from the thread that owns the GLib objects reachable
///   through the error (the main/engine thread for every current caller).
unsafe fn take_gerror(err: *mut wpe::GError) -> String {
    if err.is_null() {
        return "(no error set)".to_string();
    }
    // SAFETY: `err` is a live, owned `GError` per caller contract.
    let msg_ptr = unsafe { (*err).message };
    let msg = if msg_ptr.is_null() {
        "(null message)".to_string()
    } else {
        // SAFETY: glib guarantees a NUL-terminated message; the read is
        // bounded by the shared native-diagnostic ceiling.
        unsafe {
            crate::native_diagnostic::read_bounded_diagnostic(
                msg_ptr,
                crate::native_diagnostic::MAX_NATIVE_DIAGNOSTIC_BYTES,
            )
        }
    };
    // SAFETY: the caller guarantees sole ownership; freed exactly once.
    unsafe { wpe::g_error_free(err) };
    msg
}

// Owns the session-bus `GDBusConnection` returned by `g_bus_get_sync` and
// releases it once on drop, so every return path in `A11yBus::connect` after
// acquisition funnels through a single unref instead of manual per-path ones.
struct SessionConn {
    conn: *mut c_void,
}

impl SessionConn {
    fn new(conn: *mut c_void) -> Self {
        Self { conn }
    }

    fn as_ptr(&self) -> *mut c_void {
        self.conn
    }
}

impl Drop for SessionConn {
    fn drop(&mut self) {
        // SAFETY: this guard owns the session connection and drops once.
        unsafe { session_unref(self.conn) };
    }
}

// SAFETY: `conn` must be the owned session `GDBusConnection`.
#[cfg(not(test))]
unsafe fn session_unref(conn: *mut c_void) {
    // SAFETY: forwarded contract from the caller.
    unsafe { wpe::g_object_unref(conn) };
}

#[cfg(test)]
unsafe fn session_unref(conn: *mut c_void) {
    tests::note_session_unref(conn);
}

// Turn the copied broker address into the final result while consuming the
// session guard, so the connection is released once on every path: a failed,
// malformed, or over-budget parse (carried in `address`), an empty address, and
// a usable address handed to the a11y connection.
fn finish_connect_address(
    guard: SessionConn,
    address: Result<String, A11yError>,
) -> Result<String, A11yError> {
    let _guard = guard;
    let addr = address?;
    if addr.is_empty() {
        return Err(A11yError::NoA11yBus(
            "GetAddress returned an empty address".into(),
        ));
    }
    Ok(addr)
}

impl A11yBus {
    /// Connect to the AT-SPI bus, asking the session bus broker for its address
    /// (`org.a11y.Bus.GetAddress`) - the same handshake every AT client uses.
    ///
    /// # Errors
    ///
    /// [`A11yError::NoA11yBus`] if the session bus, the broker, or the a11y bus
    /// itself is unreachable; [`A11yError::NativeStringTooLong`] if the broker
    /// returns an address over [`MAX_A11Y_STRING_BYTES`].
    pub fn connect() -> Result<Self, A11yError> {
        let mut err: *mut wpe::GError = core::ptr::null_mut();
        // SAFETY: standard g_bus_get_sync call; error out-param initialised.
        let session =
            unsafe { wpe::g_bus_get_sync(G_BUS_TYPE_SESSION, core::ptr::null_mut(), &mut err) };
        if session.is_null() {
            // SAFETY: the call failed, so `err` is set and owned here.
            return Err(A11yError::NoA11yBus(format!("session bus: {}", unsafe {
                take_gerror(err)
            })));
        }
        // The session connection is owned from here on. A single RAII guard
        // releases it once on every post-acquisition return path.
        let guard = SessionConn::new(session);
        let address: Result<String, A11yError> = {
            let dest = CString::new("org.a11y.Bus").expect("literal has no NUL");
            let path = CString::new("/org/a11y/bus").expect("literal has no NUL");
            let iface = CString::new("org.a11y.Bus").expect("literal has no NUL");
            let method = CString::new("GetAddress").expect("literal has no NUL");
            let mut e2: *mut wpe::GError = core::ptr::null_mut();
            // SAFETY: a well-formed no-argument D-Bus call.
            let reply = unsafe {
                wpe::g_dbus_connection_call_sync(
                    guard.as_ptr(),
                    dest.as_ptr(),
                    path.as_ptr(),
                    iface.as_ptr(),
                    method.as_ptr(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    0,
                    DBUS_TIMEOUT_MS,
                    core::ptr::null_mut(),
                    &mut e2,
                )
            };
            if reply.is_null() {
                // SAFETY: the call failed, so `e2` is set and owned here.
                Err(A11yError::NoA11yBus(format!("GetAddress: {}", unsafe {
                    take_gerror(e2)
                })))
            } else {
                // Reply is `(s)`; child 0 is a retained native string and gets
                // the same per-string pre-copy check as any tree string.
                // SAFETY: reply is an owned tuple variant with one child.
                unsafe {
                    let child = wpe::g_variant_get_child_value(reply, 0);
                    let mut budget = WalkStringBudget::new(MAX_A11Y_STRING_BYTES);
                    let owned =
                        copy_variant_string(child, A11yStringKind::A11yBusAddress, &mut budget);
                    wpe::g_variant_unref(child);
                    wpe::g_variant_unref(reply);
                    owned
                }
            }
        };
        // Consumes the guard, releasing the session once on every path below.
        let addr = finish_connect_address(guard, address)?;
        let c_addr = CString::new(addr.clone())
            .map_err(|_| A11yError::NoA11yBus("a11y bus address contains a NUL".into()))?;
        let mut e3: *mut wpe::GError = core::ptr::null_mut();
        // SAFETY: connecting to a bus by address with bus-client flags.
        let conn = unsafe {
            wpe::g_dbus_connection_new_for_address_sync(
                c_addr.as_ptr(),
                DBUS_CONN_FLAGS,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut e3,
            )
        };
        if conn.is_null() {
            return Err(A11yError::NoA11yBus(format!(
                "connect to {addr}: {}",
                // SAFETY: the call failed, so `e3` is set and owned.
                unsafe { take_gerror(e3) }
            )));
        }
        Ok(Self { conn })
    }

    /// Call `interface.method()` with no arguments on `(bus_name, path)`.
    ///
    /// Returns the owned reply variant; the caller unrefs it.
    fn call0(
        &self,
        bus_name: &str,
        path: &str,
        interface: &str,
        method: &str,
    ) -> Result<*mut c_void, A11yError> {
        let bn =
            CString::new(bus_name).map_err(|_| A11yError::DbusCall("NUL in bus name".into()))?;
        let p = CString::new(path).map_err(|_| A11yError::DbusCall("NUL in path".into()))?;
        let i =
            CString::new(interface).map_err(|_| A11yError::DbusCall("NUL in interface".into()))?;
        let m = CString::new(method).map_err(|_| A11yError::DbusCall("NUL in method".into()))?;
        let mut err: *mut wpe::GError = core::ptr::null_mut();
        // SAFETY: all pointers are live CStrings; timeout is finite.
        let reply = unsafe {
            wpe::g_dbus_connection_call_sync(
                self.conn,
                bn.as_ptr(),
                p.as_ptr(),
                i.as_ptr(),
                m.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                DBUS_TIMEOUT_MS,
                core::ptr::null_mut(),
                &mut err,
            )
        };
        if reply.is_null() {
            // SAFETY: the call failed, so `err` is set and owned.
            return Err(A11yError::DbusCall(format!(
                "{interface}.{method}: {}",
                unsafe { take_gerror(err) }
            )));
        }
        Ok(reply)
    }

    /// `org.freedesktop.DBus.Properties.Get(interface, property)` returning a
    /// string, used for the `Name` property.
    fn get_string_property(
        &self,
        bus_name: &str,
        path: &str,
        interface: &str,
        property: &str,
        kind: A11yStringKind,
        budget: &mut WalkStringBudget,
    ) -> Result<String, A11yError> {
        let bn =
            CString::new(bus_name).map_err(|_| A11yError::DbusCall("NUL in bus name".into()))?;
        let p = CString::new(path).map_err(|_| A11yError::DbusCall("NUL in path".into()))?;
        let pi = CString::new("org.freedesktop.DBus.Properties").expect("literal");
        let pm = CString::new("Get").expect("literal");
        let fmt = CString::new("(ss)").expect("literal");
        let arg_iface = CString::new(interface).map_err(|_| A11yError::DbusCall("NUL".into()))?;
        let arg_prop = CString::new(property).map_err(|_| A11yError::DbusCall("NUL".into()))?;
        let mut err: *mut wpe::GError = core::ptr::null_mut();
        // SAFETY: `g_variant_new("(ss)", a, b)` matches the declared arity; the
        // floating result is consumed by the call.
        let reply = unsafe {
            let params = wpe::g_variant_new(fmt.as_ptr(), arg_iface.as_ptr(), arg_prop.as_ptr());
            wpe::g_dbus_connection_call_sync(
                self.conn,
                bn.as_ptr(),
                p.as_ptr(),
                pi.as_ptr(),
                pm.as_ptr(),
                params,
                core::ptr::null(),
                0,
                DBUS_TIMEOUT_MS,
                core::ptr::null_mut(),
                &mut err,
            )
        };
        if reply.is_null() {
            // SAFETY: the call failed, so `err` is set and owned.
            return Err(A11yError::DbusCall(format!(
                "Get({property}): {}",
                unsafe { take_gerror(err) }
            )));
        }
        // SAFETY: the reply is `(v)`; each owned variant is released after copying.
        unsafe {
            let child = wpe::g_variant_get_child_value(reply, 0);
            let inner = wpe::g_variant_get_variant(child);
            let string = copy_variant_string(inner, kind, budget);
            wpe::g_variant_unref(inner);
            wpe::g_variant_unref(child);
            wpe::g_variant_unref(reply);
            string
        }
    }

    /// `org.a11y.atspi.Accessible.GetRole()` → the AT-SPI role number.
    fn get_role(&self, bus_name: &str, path: &str) -> Result<u32, A11yError> {
        let reply = self.call0(bus_name, path, "org.a11y.atspi.Accessible", "GetRole")?;
        // Reply is `(u)`.
        // SAFETY: documented reply shape; children unref'd.
        let role = unsafe {
            if wpe::g_variant_n_children(reply) != 1 {
                wpe::g_variant_unref(reply);
                return Err(A11yError::UnexpectedReply("GetRole arity != 1".into()));
            }
            let child = wpe::g_variant_get_child_value(reply, 0);
            let r = wpe::g_variant_get_uint32(child);
            wpe::g_variant_unref(child);
            wpe::g_variant_unref(reply);
            r
        };
        Ok(role)
    }

    /// `org.a11y.atspi.Accessible.GetChildren()` → `[(bus_name, object_path)]`,
    /// clamped to `cap` children before anything is allocated or fetched.
    ///
    /// `cap` comes from `child_arity_cap`, so one hostile node cannot reserve
    /// memory or spend D-Bus round trips proportional to a page-chosen arity.
    /// The returned [`ChildList::truncated`] says whether the page reported more
    /// children than were read.
    fn get_children(
        &self,
        bus_name: &str,
        path: &str,
        cap: usize,
        budget: &mut WalkStringBudget,
    ) -> Result<ChildList, A11yError> {
        let reply = self.call0(bus_name, path, "org.a11y.atspi.Accessible", "GetChildren")?;
        // SAFETY: the reply is `(a(so))`; each owned variant is released after copying.
        unsafe {
            if wpe::g_variant_n_children(reply) != 1 {
                wpe::g_variant_unref(reply);
                return Err(A11yError::UnexpectedReply("GetChildren arity != 1".into()));
            }
            let array = wpe::g_variant_get_child_value(reply, 0);
            let out = read_children_capped(&VariantChildArray { array }, cap, budget);
            wpe::g_variant_unref(array);
            wpe::g_variant_unref(reply);
            out
        }
    }

    /// Read one node (role + accessible name) without recursing.
    fn read_node(
        &self,
        bus_name: &str,
        path: &str,
        budget: &mut WalkStringBudget,
    ) -> Result<(u32, String), A11yError> {
        let role = self.get_role(bus_name, path)?;
        let name = self.get_string_property(
            bus_name,
            path,
            "org.a11y.atspi.Accessible",
            "Name",
            A11yStringKind::AccessibleName,
            budget,
        )?;
        Ok((role, name))
    }

    /// `org.freedesktop.DBus.Properties.Get` for an `i`-typed property.
    fn get_int32_property(
        &self,
        bus_name: &str,
        path: &str,
        interface: &str,
        property: &str,
    ) -> Result<i32, A11yError> {
        let bn =
            CString::new(bus_name).map_err(|_| A11yError::DbusCall("NUL in bus name".into()))?;
        let p = CString::new(path).map_err(|_| A11yError::DbusCall("NUL in path".into()))?;
        let pi = CString::new("org.freedesktop.DBus.Properties").expect("literal");
        let pm = CString::new("Get").expect("literal");
        let fmt = CString::new("(ss)").expect("literal");
        let arg_iface = CString::new(interface).map_err(|_| A11yError::DbusCall("NUL".into()))?;
        let arg_prop = CString::new(property).map_err(|_| A11yError::DbusCall("NUL".into()))?;
        let mut err: *mut wpe::GError = core::ptr::null_mut();
        // SAFETY: `(ss)` matches the two CString arguments; the floating result
        // is consumed by the call.
        let reply = unsafe {
            let params = wpe::g_variant_new(fmt.as_ptr(), arg_iface.as_ptr(), arg_prop.as_ptr());
            wpe::g_dbus_connection_call_sync(
                self.conn,
                bn.as_ptr(),
                p.as_ptr(),
                pi.as_ptr(),
                pm.as_ptr(),
                params,
                core::ptr::null(),
                0,
                DBUS_TIMEOUT_MS,
                core::ptr::null_mut(),
                &mut err,
            )
        };
        if reply.is_null() {
            // SAFETY: the call failed, so `err` is set and owned.
            return Err(A11yError::DbusCall(format!(
                "Get({property}): {}",
                unsafe { take_gerror(err) }
            )));
        }
        // Reply is `(v)` boxing an `i`.
        // SAFETY: documented reply shape; every intermediate variant unref'd.
        let out = unsafe {
            let child = wpe::g_variant_get_child_value(reply, 0);
            let inner = wpe::g_variant_get_variant(child);
            let v = wpe::g_variant_get_int32(inner);
            wpe::g_variant_unref(inner);
            wpe::g_variant_unref(child);
            wpe::g_variant_unref(reply);
            v
        };
        Ok(out)
    }

    /// Call an `org.a11y.atspi.Action` method taking a single `i` index.
    ///
    /// Returns the owned reply variant; the caller unrefs it.
    fn call_action_index(
        &self,
        bus_name: &str,
        path: &str,
        method: &str,
        index: i32,
    ) -> Result<*mut c_void, A11yError> {
        let bn =
            CString::new(bus_name).map_err(|_| A11yError::DbusCall("NUL in bus name".into()))?;
        let p = CString::new(path).map_err(|_| A11yError::DbusCall("NUL in path".into()))?;
        let i = CString::new("org.a11y.atspi.Action").expect("literal");
        let m = CString::new(method).map_err(|_| A11yError::DbusCall("NUL in method".into()))?;
        let mut err: *mut wpe::GError = core::ptr::null_mut();
        // SAFETY: `g_variant_new_int32` returns a floating ref which
        // `g_variant_new_tuple` consumes; the resulting floating tuple is
        // consumed by `g_dbus_connection_call_sync`. Nothing is leaked and
        // nothing is unref'd twice.
        let reply = unsafe {
            let idx = wpe::g_variant_new_int32(index);
            let children = [idx];
            let params = wpe::g_variant_new_tuple(children.as_ptr(), 1);
            wpe::g_dbus_connection_call_sync(
                self.conn,
                bn.as_ptr(),
                p.as_ptr(),
                i.as_ptr(),
                m.as_ptr(),
                params,
                core::ptr::null(),
                0,
                DBUS_TIMEOUT_MS,
                core::ptr::null_mut(),
                &mut err,
            )
        };
        if reply.is_null() {
            // SAFETY: the call failed, so `err` is set and owned.
            return Err(A11yError::DbusCall(format!(
                "Action.{method}({index}): {}",
                unsafe { take_gerror(err) }
            )));
        }
        Ok(reply)
    }

    /// `org.a11y.atspi.Action.GetName(index)` - the machine-readable action
    /// name (`"click"`, `"press"`, `"jump"`), not the localized one.
    ///
    /// # Errors
    ///
    /// [`A11yError::DbusCall`] if the object does not implement `Action`, or
    /// [`A11yError::NativeStringTooLong`] if the native name exceeds the
    /// per-string ceiling.
    pub fn action_name(&self, bus_name: &str, path: &str, index: i32) -> Result<String, A11yError> {
        let mut budget = WalkStringBudget::new(MAX_A11Y_STRING_BYTES);
        self.action_name_with_budget(bus_name, path, index, &mut budget)
    }

    fn action_name_with_budget(
        &self,
        bus_name: &str,
        path: &str,
        index: i32,
        budget: &mut WalkStringBudget,
    ) -> Result<String, A11yError> {
        let reply = self.call_action_index(bus_name, path, "GetName", index)?;
        // Reply is `(s)`.
        // SAFETY: documented reply shape; children unref'd.
        unsafe {
            if wpe::g_variant_n_children(reply) != 1 {
                wpe::g_variant_unref(reply);
                return Err(A11yError::UnexpectedReply("GetName arity != 1".into()));
            }
            let child = wpe::g_variant_get_child_value(reply, 0);
            let out = copy_variant_string(child, A11yStringKind::ActionName, budget);
            wpe::g_variant_unref(child);
            wpe::g_variant_unref(reply);
            out
        }
    }

    /// Every machine-readable action name on `(bus_name, path)`, in index order.
    ///
    /// An object that does not implement `Action` has no actions - that is a
    /// normal answer for a heading or a paragraph, so the `NActions` read
    /// failing yields an empty list rather than an error. A *name* read failing
    /// after `NActions` succeeded stops the list there, because an action whose
    /// name that could not read must not be guessed at.
    ///
    /// # Errors
    ///
    /// A native action name crossing the per-string or cumulative byte ceiling
    /// is returned as its typed [`A11yError`] instead of a partial action list.
    pub fn action_names(&self, bus_name: &str, path: &str) -> Result<Vec<String>, A11yError> {
        let mut budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
        self.action_names_with_budget(bus_name, path, &mut budget)
    }

    fn action_names_with_budget(
        &self,
        bus_name: &str,
        path: &str,
        budget: &mut WalkStringBudget,
    ) -> Result<Vec<String>, A11yError> {
        let Ok(n) = self.get_int32_property(bus_name, path, "org.a11y.atspi.Action", "NActions")
        else {
            return Ok(Vec::new());
        };
        // Bound the loop: `n` is page-supplied. A control with more than a
        // handful of actions is pathological, and AT only ever uses the first.
        let n = n.clamp(0, MAX_ACTIONS_PER_NODE);
        let mut out = Vec::new();
        for i in 0..n {
            match self.action_name_with_budget(bus_name, path, i, budget) {
                Ok(name) => out.push(name),
                Err(error) if error.is_string_budget_refusal() => return Err(error),
                Err(_) => break,
            }
        }
        Ok(out)
    }

    /// `org.a11y.atspi.Action.DoAction(index)` - perform the action.
    ///
    /// This is the call that makes a published page control operable: the same
    /// entry point a screen reader uses, so a control reachable here is
    /// reachable by AT.
    ///
    /// # Why this one call is asynchronous
    ///
    /// Every other call in this module is `..._call_sync`, and reading the tree
    /// that way is fine. `DoAction` is different, and this was measured, not
    /// predicted: the synchronous form fails with `Timeout was reached` after
    /// the full 5 s, on a page whose button was found, addressed and correctly
    /// reported a `press` action.
    ///
    /// The reason is a deadlock. Activating a DOM element makes WebKit's
    /// WebProcess dispatch a real click, and completing that needs IPC with
    /// this (the UI) process. `..._call_sync` blocks this thread and stops
    /// servicing the GLib main context, so the WebProcess waits while this code
    /// wait on it, until the D-Bus timeout breaks the tie. Reading a role or a
    /// name never hits this because it is answered from the WebProcess's own
    /// cached tree.
    ///
    /// So the request is issued asynchronously and a bounded [`wpe::GMainLoop`]
    /// runs until the reply lands - which is what lets the UI process answer
    /// the WebProcess and the action complete.
    ///
    /// # Bounded, and safe on the timeout path
    ///
    /// A `g_timeout_add` deadline quits the loop, and on that path the
    /// [`GCancellable`](wpe::g_cancellable_new) is cancelled and the context
    /// drained until the callback is observed - the ownership rule: a callback
    /// firing later against a freed state box is a use-after-free. If draining
    /// cannot prove the callback ran, the state box and every GLib object the
    /// callback dereferences through it (the main loop, the cancellable) are
    /// retained deliberately rather than risk that.
    ///
    /// Returns what the page reported: `true` on success, `false` if the object
    /// refused. A `false` is a real answer, not an error.
    ///
    /// # Errors
    ///
    /// [`A11yError::DbusCall`] if the object does not implement `Action`, the
    /// call fails, or the deadline expires; [`A11yError::UnexpectedReply`] on a
    /// wrong reply shape.
    pub fn do_action(&self, bus_name: &str, path: &str, index: i32) -> Result<bool, A11yError> {
        self.do_action_with_deadline(bus_name, path, index, DBUS_TIMEOUT_MS as u32)
    }

    /// [`do_action`](Self::do_action) with an explicit deadline in
    /// milliseconds.
    ///
    /// Exists so the timeout path can be driven on demand: with a 1 ms
    /// deadline the deadline source must win, which exercises cancel + drain +
    /// retention on every run instead of only when a WebProcess misbehaves.
    /// The same deadline technique makes the snapshot timeout
    /// load-bearing rather than merely present.
    ///
    /// # Errors
    ///
    /// As [`do_action`](Self::do_action).
    pub fn do_action_with_deadline(
        &self,
        bus_name: &str,
        path: &str,
        index: i32,
        deadline_ms: u32,
    ) -> Result<bool, A11yError> {
        self.do_action_deadline_and_drain_cap(bus_name, path, index, deadline_ms, DRAIN_CAP_MS)
    }

    /// [`do_action_with_deadline`](Self::do_action_with_deadline) with an
    /// explicit drain cap, so the give-up branch - drain cap expires while
    /// the cancelled callback is still outstanding, and every object the
    /// callback can reach is retained - can be reached deterministically.
    ///
    /// A `drain_cap_ms` of `0` returns from the drain loop before it iterates
    /// the context, so the callback cannot complete during this call and the
    /// retention path runs on every invocation. That is how the cap-expiry gate
    /// proves the connection/loop/cancellable/state retention is correct rather
    /// than merely present, without needing a WebProcess that wedges mid-call.
    ///
    /// # Errors
    ///
    /// As [`do_action`](Self::do_action).
    pub fn do_action_deadline_and_drain_cap(
        &self,
        bus_name: &str,
        path: &str,
        index: i32,
        deadline_ms: u32,
        drain_cap_ms: u64,
    ) -> Result<bool, A11yError> {
        let bn =
            CString::new(bus_name).map_err(|_| A11yError::DbusCall("NUL in bus name".into()))?;
        let p = CString::new(path).map_err(|_| A11yError::DbusCall("NUL in path".into()))?;
        let iface = CString::new("org.a11y.atspi.Action").expect("literal");
        let method = CString::new("DoAction").expect("literal");

        // SAFETY: NULL context = default; not running.
        let main_loop = unsafe { wpe::g_main_loop_new(core::ptr::null_mut(), 0) };
        if main_loop.is_null() {
            return Err(A11yError::DbusCall("g_main_loop_new returned NULL".into()));
        }
        // SAFETY: a cancellable owned here.
        let cancellable = unsafe { wpe::g_cancellable_new() };

        let state_ptr = Box::into_raw(Box::new(DoActionState {
            main_loop,
            conn: self.conn,
            cancellable,
            reply: core::ptr::null_mut(),
            error: None,
            callback_fired: false,
            deadline_fired: false,
            abandoned: false,
        }));

        // The deadline must be installed BEFORE the call, so a call that never
        // completes is still bounded.
        // SAFETY: `on_do_action_deadline` matches GSourceFunc; state outlives
        // the source (removed below, or drained before free).
        let deadline_tag = unsafe {
            wpe::g_timeout_add(
                deadline_ms,
                on_do_action_deadline,
                state_ptr.cast::<c_void>(),
            )
        };

        // SAFETY: all strings are live CStrings; the `(i)` tuple is floating and
        // consumed by the call; `on_do_action_ready` matches
        // GAsyncReadyCallback and receives `state_ptr`.
        unsafe {
            let idx = wpe::g_variant_new_int32(index);
            let children = [idx];
            let params = wpe::g_variant_new_tuple(children.as_ptr(), 1);
            wpe::g_dbus_connection_call(
                self.conn,
                bn.as_ptr(),
                p.as_ptr(),
                iface.as_ptr(),
                method.as_ptr(),
                params,
                core::ptr::null(),
                0,
                DBUS_TIMEOUT_MS,
                cancellable,
                on_do_action_ready,
                state_ptr.cast::<c_void>(),
            );
            // Runs until the reply callback or the deadline quits it. This is
            // what services the WebProcess's IPC and breaks the deadlock.
            wpe::g_main_loop_run(main_loop);
        }

        // SAFETY: single-threaded; the box is live and both flags are written
        // only by callbacks dispatched on this thread, which finished before
        // `g_main_loop_run` returned.
        let retirement = unsafe {
            retire_do_action_deadline(&*state_ptr, deadline_tag, &mut NativeSourceRemover)
        };
        if !retirement.completion_resolved() {
            // The async call is still outstanding and its callback would later
            // write into this box: cancel and drain until this code can prove it ran.
            // SAFETY: the cancellable.
            unsafe { wpe::g_cancellable_cancel(cancellable) };
            let start = std::time::Instant::now();
            let cap = std::time::Duration::from_millis(drain_cap_ms);
            loop {
                // SAFETY: single-threaded; flipped only by the callback.
                if unsafe { (*state_ptr).callback_fired } {
                    break;
                }
                if start.elapsed() >= cap {
                    // Cannot prove the callback ran within the cap, so hand it
                    // ownership instead of freeing anything it can still reach
                    // The connection is owned by this
                    // `A11yBus`, which the caller may drop while the call is
                    // still outstanding, so take an extra strong ref here; the
                    // callback releases it (and the loop, cancellable, reply and
                    // box) when it finally fires. This is a *transfer*, not a
                    // permanent leak: `free_abandoned_do_action` runs on the
                    // callback and bumps `ABANDONED_CLEANUPS`.
                    // SAFETY: `state.conn` is the live GDBusConnection this
                    // A11yBus owns; the extra ref keeps it alive for the
                    // pending callback.
                    unsafe { wpe::g_object_ref((*state_ptr).conn) };
                    // SAFETY: single-threaded; the callback has not run yet, so
                    // setting the transfer flag races nothing.
                    unsafe { (*state_ptr).abandoned = true };
                    return Err(A11yError::DbusCall(format!(
                        "Action.DoAction({index}): deadline reached and the \
                         cancelled callback did not complete within \
                         {drain_cap_ms}ms; ownership of the call's state, main \
                         loop, cancellable and connection was transferred to the \
                         callback, which frees them when it fires"
                    )));
                }
                // SAFETY: draining the default context, non-blocking.
                unsafe { wpe::g_main_context_iteration(core::ptr::null_mut(), 0) };
            }
        }

        // SAFETY: the callback has provably run, so nothing else points here.
        let state = unsafe { Box::from_raw(state_ptr) };
        // SAFETY: its own objects.
        unsafe {
            wpe::g_object_unref(cancellable);
            wpe::g_main_loop_unref(main_loop);
        }

        if let Some(msg) = state.error {
            return Err(A11yError::DbusCall(format!(
                "Action.DoAction({index}): {msg}"
            )));
        }
        let reply = state.reply;
        if reply.is_null() {
            return Err(A11yError::DbusCall(format!(
                "Action.DoAction({index}): no reply and no error"
            )));
        }
        // Reply is `(b)`.
        // SAFETY: documented reply shape; children unref'd.
        let ok = unsafe {
            if wpe::g_variant_n_children(reply) != 1 {
                wpe::g_variant_unref(reply);
                return Err(A11yError::UnexpectedReply("DoAction arity != 1".into()));
            }
            let child = wpe::g_variant_get_child_value(reply, 0);
            // `gboolean` is a C int: any non-zero is true.
            let b = wpe::g_variant_get_boolean(child) != 0;
            wpe::g_variant_unref(child);
            wpe::g_variant_unref(reply);
            b
        };
        Ok(ok)
    }

    /// Walk the accessible tree rooted at `(bus_name, path)`.
    ///
    /// `max_depth` and `max_nodes` bound the walk so a pathological page cannot
    /// make this run unbounded - the same discipline the frame path uses.
    /// [`MAX_A11Y_STRING_BYTES`] bounds every retained native string and
    /// [`MAX_A11Y_WALK_STRING_BYTES`] bounds their cumulative bytes across this
    /// call. A further bound is per node: `child_arity_cap` clamps the
    /// page-reported child arity against the remaining node budget (and
    /// `MAX_CHILDREN_PER_NODE`) before any allocation or child fetch, so one
    /// node cannot monopolise memory and D-Bus round trips inside an otherwise
    /// bounded walk. Whatever a clamp dropped is reported through
    /// [`A11yNode::children_truncated`] / [`A11yNode::subtree_truncated`].
    ///
    /// # Errors
    ///
    /// Any AT-SPI call failure on the root; failures deeper in the tree
    /// prune that subtree rather than failing the whole walk (a node can vanish
    /// mid-walk as the page mutates, which is not the error). Native string
    /// limit failures at any depth always refuse the entire walk with
    /// [`A11yError::NativeStringTooLong`] or
    /// [`A11yError::WalkStringBudgetExceeded`].
    pub fn walk(
        &self,
        bus_name: &str,
        path: &str,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<A11yNode, A11yError> {
        let mut node_budget = max_nodes;
        let mut string_budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
        // Root identities arrived through the bounded plug-id path, but each is
        // copied again into the retained root node, so this walk charges those
        // concrete allocations too.
        let bus_name = string_budget.copy_rust_string(bus_name, A11yStringKind::BusName)?;
        let path = string_budget.copy_rust_string(path, A11yStringKind::ObjectPath)?;
        self.walk_inner(
            bus_name,
            path,
            max_depth,
            &mut node_budget,
            &mut string_budget,
        )
    }

    fn walk_inner(
        &self,
        bus_name: String,
        path: String,
        depth_left: usize,
        node_budget: &mut usize,
        string_budget: &mut WalkStringBudget,
    ) -> Result<A11yNode, A11yError> {
        let (role, name) = self.read_node(&bus_name, &path, string_budget)?;
        *node_budget = node_budget.saturating_sub(1);
        // Record the address and the machine-readable actions:
        // without them the tree is readable and inert, and an AT activation has
        // nowhere to go.
        let actions = self.action_names_with_budget(&bus_name, &path, string_budget)?;
        let mut node = A11yNode {
            role,
            name,
            children: Vec::new(),
            bus_name,
            path,
            actions,
            children_truncated: false,
        };
        if depth_left == 0 || *node_budget == 0 {
            return Ok(node);
        }
        // Clamp the page-reported arity against what this walk can still spend,
        // BEFORE `GetChildren`'s reply is allocated or iterated.
        let cap = child_arity_cap(*node_budget);
        // A child that fails mid-walk prunes its subtree; the walk continues.
        // String-budget refusals are different: publishing a prefix would hide
        // the security limit, so they abort the walk as a typed error.
        let kids = match self.get_children(&node.bus_name, &node.path, cap, string_budget) {
            Ok(kids) => kids,
            Err(error) if error.is_string_budget_refusal() => return Err(error),
            Err(_) => return Ok(node),
        };
        node.children_truncated = kids.truncated;
        for (child_bus, child_path) in kids.children {
            if *node_budget == 0 {
                // The budget ran out while this child was still unvisited,
                // so the list published here is a prefix. Say so rather than
                // presenting it as the whole child list.
                node.children_truncated = true;
                break;
            }
            match self.walk_inner(
                child_bus,
                child_path,
                depth_left - 1,
                node_budget,
                string_budget,
            ) {
                Ok(child) => node.children.push(child),
                Err(error) if error.is_string_budget_refusal() => return Err(error),
                Err(_) => {}
            }
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests;
