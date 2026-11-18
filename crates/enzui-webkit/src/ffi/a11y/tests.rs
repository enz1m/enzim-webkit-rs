//! Unit tests for the pure logic of the a11y bridge.
//!
//! These cover the parts that do not need a browser: plug-id parsing (which is
//! genuinely subtle - D-Bus unique names contain colons), the tree helpers the
//! gate asserts through, the foreign-pointer readers (`take_gerror`,
//! `interface_key`), and dispatch-order retirement. The end-to-end "a real
//! page's tree crosses the process seam" proof is the `wpe_a11y` integration
//! gate, which needs real WebKit and a real AT-SPI bus.

use super::*;
use std::ffi::CString;

// -------------------------------------------------------------------------
// split_plug_id
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// A11yNode helpers
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Native string boundaries and the shared walk budget
// -------------------------------------------------------------------------

/// Route a real GLib string variant through the production length-first copy.
fn copy_native_fixture(
    value: &str,
    kind: A11yStringKind,
    budget: &mut WalkStringBudget,
) -> Result<String, A11yError> {
    let value = CString::new(value).expect("fixture has no interior NUL");
    // SAFETY: GLib copies this live CString into a new floating variant; the
    // production reader borrows it only until this code unrefs it below.
    unsafe {
        let variant = wpe::g_variant_new_string(value.as_ptr());
        let out = copy_variant_string(variant, kind, budget);
        wpe::g_variant_unref(variant);
        out
    }
}

/// Build a real `a(so)` variant like `Accessible.GetChildren` returns.
fn native_child_array(bus_name: &str, path: &str) -> *mut c_void {
    let bus_name = CString::new(bus_name).expect("fixture bus has no NUL");
    let path = CString::new(path).expect("fixture path has no NUL");
    // SAFETY: both CStrings are live for the constructors. The tuple consumes
    // the two floating children and the array consumes the floating tuple.
    unsafe {
        let bus = wpe::g_variant_new_string(bus_name.as_ptr());
        let path = wpe::g_variant_new_object_path(path.as_ptr());
        let tuple_children = [bus, path];
        let tuple = wpe::g_variant_new_tuple(tuple_children.as_ptr(), tuple_children.len());
        let array_children = [tuple];
        wpe::g_variant_new_array(
            core::ptr::null(),
            array_children.as_ptr(),
            array_children.len(),
        )
    }
}

#[test]
fn native_child_routing_identity_is_exact_or_refused_never_truncated() {
    let array = native_child_array(":1.42", "/org/a11y/atspi/accessible/button");
    let mut ordinary_budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
    let ordinary = read_children_capped(&VariantChildArray { array }, 1, &mut ordinary_budget)
        .expect("ordinary native child identity");
    // SAFETY: the reader has released all owned child references; this is the
    // original floating array.
    unsafe { wpe::g_variant_unref(array) };
    assert_eq!(
        ordinary.children,
        vec![(
            ":1.42".to_owned(),
            "/org/a11y/atspi/accessible/button".to_owned()
        )],
        "positive control: an ordinary route survives byte-for-byte"
    );

    let oversized_bus = "b".repeat(MAX_A11Y_STRING_BYTES + 1);
    let array = native_child_array(&oversized_bus, "/org/a11y/valid_path");
    let mut refused_budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
    let error = read_children_capped(&VariantChildArray { array }, 1, &mut refused_budget)
        .expect_err("an oversized routing identity must refuse the child list");
    // SAFETY: as above; the failed reader also released its child references.
    unsafe { wpe::g_variant_unref(array) };
    assert_eq!(
        error,
        A11yError::NativeStringTooLong {
            kind: A11yStringKind::BusName,
            bytes: MAX_A11Y_STRING_BYTES + 1,
            max_bytes: MAX_A11Y_STRING_BYTES,
        },
        "a bus identity is refused by type, never shortened into a different destination"
    );
    assert_eq!(refused_budget.retained, 0);

    let oversized_path = format!("/{}", "p".repeat(MAX_A11Y_STRING_BYTES));
    let array = native_child_array(":1.42", &oversized_path);
    let mut refused_budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
    let error = read_children_capped(&VariantChildArray { array }, 1, &mut refused_budget)
        .expect_err("an oversized object path must refuse the child list");
    // SAFETY: as above.
    unsafe { wpe::g_variant_unref(array) };
    assert_eq!(
        error,
        A11yError::NativeStringTooLong {
            kind: A11yStringKind::ObjectPath,
            bytes: MAX_A11Y_STRING_BYTES + 1,
            max_bytes: MAX_A11Y_STRING_BYTES,
        },
        "an object path is refused by type, never shortened into a different route"
    );
    assert_eq!(
        refused_budget.retained,
        ":1.42".len(),
        "only the already accepted bus name is retained/charged; no path prefix is copied"
    );
}

#[test]
fn many_valid_native_strings_stop_at_the_cumulative_walk_ceiling() {
    let piece = "p".repeat(MAX_A11Y_STRING_BYTES);
    let mut budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
    let mut retained = Vec::new();

    for i in 0..(MAX_A11Y_WALK_STRING_BYTES / piece.len()) {
        let kind = if i % 2 == 0 {
            A11yStringKind::AccessibleName
        } else {
            A11yStringKind::ActionName
        };
        let copied =
            copy_native_fixture(&piece, kind, &mut budget).expect("exact cumulative limit");
        assert_eq!(copied, piece);
        retained.push(copied);
    }
    assert_eq!(
        retained.iter().map(String::len).sum::<usize>(),
        MAX_A11Y_WALK_STRING_BYTES
    );
    assert_eq!(
        budget.retained, MAX_A11Y_WALK_STRING_BYTES,
        "positive control: the production cumulative exact limit succeeds"
    );

    assert_eq!(
        copy_native_fixture("x", A11yStringKind::BusName, &mut budget),
        Err(A11yError::WalkStringBudgetExceeded {
            kind: A11yStringKind::BusName,
            bytes: 1,
            retained_bytes: MAX_A11Y_WALK_STRING_BYTES,
            max_bytes: MAX_A11Y_WALK_STRING_BYTES,
        })
    );
    assert_eq!(
        budget.retained, MAX_A11Y_WALK_STRING_BYTES,
        "refusal leaves accepted bytes at, never above, the production ceiling"
    );
}

// -------------------------------------------------------------------------
// Per-node child arity ceiling
// -------------------------------------------------------------------------

/// A stubbed `a(so)` array that reports whatever arity it is told to and counts
/// the entries actually fetched.
///
/// This is the only way to drive the defect: a real bus never hands back an
/// array of a million children, and the bug was precisely that the reported
/// count was trusted for `Vec::with_capacity` and for the fetch loop.
struct StubChildArray {
    reported: usize,
    fetched: std::cell::Cell<usize>,
    highest_index: std::cell::Cell<Option<usize>>,
}

impl StubChildArray {
    fn new(reported: usize) -> Self {
        Self {
            reported,
            fetched: std::cell::Cell::new(0),
            highest_index: std::cell::Cell::new(None),
        }
    }
}

impl ChildArray for StubChildArray {
    fn reported_len(&self) -> usize {
        self.reported
    }

    fn entry(
        &self,
        i: usize,
        budget: &mut WalkStringBudget,
    ) -> Result<Option<(String, String)>, A11yError> {
        assert!(
            i < self.reported,
            "the reader fetched entry {i} past the reported arity {}",
            self.reported
        );
        self.fetched.set(self.fetched.get() + 1);
        let high = self.highest_index.get().map_or(i, |h| h.max(i));
        self.highest_index.set(Some(high));
        let bus = budget.copy_rust_string(":1.42", A11yStringKind::BusName)?;
        let path = budget.copy_rust_string(
            &format!("/org/a11y/atspi/accessible/{i}"),
            A11yStringKind::ObjectPath,
        )?;
        Ok(Some((bus, path)))
    }
}

#[test]
fn a_hostile_arity_allocates_and_fetches_only_the_cap_and_reports_truncation() {
    // A page/WebProcess-controlled `GetChildren` claiming a million children.
    // Before the clamp this reserved ~48 MB and performed a million fetches
    // inside a walk whose depth and node count were already "bounded".
    let stub = StubChildArray::new(1_000_000);
    let cap = 16;
    let mut budget = WalkStringBudget::new(MAX_A11Y_WALK_STRING_BYTES);
    let out = read_children_capped(&stub, cap, &mut budget).expect("identities fit budget");

    assert_eq!(
        out.children.len(),
        cap,
        "only the cap may be kept, not the reported arity"
    );
    assert_eq!(
        stub.fetched.get(),
        cap,
        "the fetch loop must run cap times, not reported-arity times"
    );
    assert_eq!(
        stub.highest_index.get(),
        Some(cap - 1),
        "the walk must stop at the cap's last index"
    );
    // The pre-allocation clamp, asserted on its own: `Vec::with_capacity(n)`
    // for a non-ZST reserves exactly `n`, and pushing at most `n` items never
    // grows it. Trusting the reported arity here reserves ~48 MB for one node.
    assert!(
        out.children.capacity() <= cap,
        "the reservation must be clamped BEFORE allocation, got capacity {} for cap {cap}",
        out.children.capacity()
    );
    assert!(
        out.truncated,
        "a clamped read must report truncation, not pretend the list is complete"
    );
}

// -------------------------------------------------------------------------
#[test]
fn wpe_registry_a11y_observation_crosses_threads() {
    use std::sync::{Arc, Barrier, mpsc};

    let accessible = core::ptr::null_mut();
    forget_accessible(accessible);

    let start = Arc::new(Barrier::new(2));
    let writer_start = Arc::clone(&start);
    let (recorded_tx, recorded_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        writer_start.wait();
        let plug = std::ffi::CString::new(":1.2443:/org/a11y/cross-thread").unwrap();
        // NULL keeps interface-key derivation host-independent, while the real
        // callback path still parses and records the plug id before refusing
        // to chain without an interface.
        record_bind(core::ptr::null_mut(), plug.as_ptr());
        recorded_tx.send(()).expect("reader still waits");
    });

    start.wait();
    recorded_rx.recv().expect("writer records before read-back");
    assert_eq!(
        plug_id_for(accessible).as_deref(),
        Some(":1.2443:/org/a11y/cross-thread"),
        "a process-wide callback observation must be visible to another thread"
    );
    writer.join().expect("writer thread completes");
    forget_accessible(accessible);
}

// -------------------------------------------------------------------------
// Session-bus connection ownership in `A11yBus::connect` (filter:
// `session_release`)
//
// `A11yBus::connect` owns the `GDBusConnection` from `g_bus_get_sync` and must
// release it once on every post-acquisition return. These tests inject the
// copied broker address result into the real ownership funnel
// (`finish_connect_address` consuming a real `SessionConn`) and count the
// release through the guard's own `Drop`, which the unit-test build routes to
// `note_session_unref` instead of a live `g_object_unref`.
// -------------------------------------------------------------------------

thread_local! {
    static SESSION_UNREF_LOG: RefCell<Vec<*mut c_void>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn note_session_unref(conn: *mut c_void) {
    SESSION_UNREF_LOG.with(|log| log.borrow_mut().push(conn));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoActionDispatch {
    Deadline,
    Completion,
}

const DO_ACTION_DEADLINE_TAG: c_uint = 73;

struct DoActionRetirement {
    self_removals: usize,
    explicit_removals: Vec<c_uint>,
}

fn dispatch_do_action_batch(batch: &[DoActionDispatch]) -> DoActionRetirement {
    let mut state = DoActionState {
        main_loop: core::ptr::null_mut(),
        conn: core::ptr::null_mut(),
        cancellable: core::ptr::null_mut(),
        reply: core::ptr::null_mut(),
        error: None,
        callback_fired: false,
        deadline_fired: false,
        abandoned: false,
    };
    let mut self_removals = 0;
    for dispatch in batch {
        match dispatch {
            DoActionDispatch::Deadline => {
                if mark_do_action_deadline(&mut state) == wpe::G_FALSE {
                    self_removals += 1;
                }
            }
            DoActionDispatch::Completion => mark_do_action_completion(&mut state),
        }
    }
    let mut remover = crate::deadline_source::RecordingRemover::default();
    retire_do_action_deadline(&state, DO_ACTION_DEADLINE_TAG, &mut remover);
    DoActionRetirement {
        self_removals,
        explicit_removals: remover.removed,
    }
}

#[test]
fn do_action_deadline_source_is_retired_exactly_once_in_every_dispatch_order() {
    for batch in [
        vec![DoActionDispatch::Deadline, DoActionDispatch::Completion],
        vec![DoActionDispatch::Completion, DoActionDispatch::Deadline],
        vec![DoActionDispatch::Completion],
        vec![DoActionDispatch::Deadline],
    ] {
        let outcome = dispatch_do_action_batch(&batch);
        assert_eq!(
            outcome.self_removals + outcome.explicit_removals.len(),
            1,
            "{batch:?} retired the deadline source {} times, not once",
            outcome.self_removals + outcome.explicit_removals.len()
        );
    }
}

// -------------------------------------------------------------------------
// take_gerror: typed-field reading, null handling, and free-exactly-once
// (filter: `take_gerror`)
// -------------------------------------------------------------------------

/// Create a real `GError` through glib so `g_error_free` is valid on it.
fn make_gerror(message: &str) -> *mut wpe::GError {
    let domain_str = CString::new("test-a11y-error-quark").expect("literal");
    // SAFETY: the CString is live for the call; `g_quark_from_string` copies
    // it into the quark table so the local buffer need not outlive this scope.
    let domain = unsafe { wpe::g_quark_from_string(domain_str.as_ptr()) };
    let c_msg = CString::new(message).expect("fixture message has no interior NUL");
    // SAFETY: a well-formed call that allocates a new `GError`; the message is
    // copied, so `c_msg` may drop afterwards.
    let err = unsafe { wpe::g_error_new_literal(domain, 1, c_msg.as_ptr()) };
    assert!(!err.is_null(), "g_error_new_literal returned NULL");
    err
}

#[test]
fn take_gerror_frees_each_error_exactly_once() {
    // Two independent GErrors freed sequentially. Asserting both messages
    // proves each was read while still live; a double-free would abort under
    // ASan or glib's debug allocator.
    let err1 = make_gerror("first error");
    let err2 = make_gerror("second error");
    // SAFETY: both are live, owned GErrors; freed one at a time.
    let msg1 = unsafe { take_gerror(err1) };
    let msg2 = unsafe { take_gerror(err2) };
    assert_eq!(msg1, "first error");
    assert_eq!(msg2, "second error");
}

// -------------------------------------------------------------------------
// interface_key: null and class-null controls
// (filter: `interface_key_null`)
// -------------------------------------------------------------------------
