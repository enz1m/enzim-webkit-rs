// The crate denies `unsafe_code` through the workspace lint table, which
// applies to integration targets too. This target is a synthetic replica of
// the native responder move-out boundary: it owns a `*mut Model` across a
// reentrant call precisely so the aliasing rule can be checked under Miri
// without a WebKit process, so the raw-pointer dispatch it models cannot be
// expressed in safe code.
#![allow(unsafe_code)]

use std::cell::Cell;
use std::rc::Rc;

type Responder = dyn FnMut(*mut Model);

struct Model {
    // Taken for the duration of a call, so an empty slot is what a nested
    // dispatch observes and refuses.
    responder: Option<Box<Responder>>,
    nested_denials: usize,
}

/// # Safety
///
/// `state` must remain a live, thread-confined model until every
/// nested dispatch has returned.
unsafe fn dispatch(state: *mut Model) -> bool {
    // SAFETY: the caller owns a live model for the complete dispatch. This
    // borrow ends after the responder is removed and before host code runs.
    let responder = unsafe {
        let state = &mut *state;
        let Some(responder) = state.responder.take() else {
            state.nested_denials += 1;
            return false;
        };
        responder
    };

    let mut responder = responder;
    responder(state);

    // SAFETY: the caller keeps the model live, and nested dispatch cannot fill
    // the empty slot because it fails closed before invoking host code.
    unsafe {
        assert!(
            (*state).responder.is_none(),
            "nested dispatch must not replace the active responder"
        );
        (*state).responder = Some(responder);
    }
    true
}

#[test]
fn nested_dispatch_does_not_alias_fn_mut_and_independent_dispatch_still_runs() {
    let pointer = Rc::new(Cell::new(std::ptr::null_mut::<Model>()));
    let calls = Rc::new(Cell::new(0));
    let nested_attempted = Rc::new(Cell::new(false));
    let nested_result = Rc::new(Cell::new(None));
    let model = Model {
        responder: Some(Box::new({
            let pointer = pointer.clone();
            let calls = calls.clone();
            let nested_attempted = nested_attempted.clone();
            let nested_result = nested_result.clone();
            move |_| {
                calls.set(calls.get() + 1);
                // Claimed before dispatching, not after it returns: a mechanism
                // that leaves the responder reachable reenters here exactly
                // once, bounding the failure to the assertions below.
                if !nested_attempted.replace(true) {
                    // SAFETY: the outer dispatch owns the live boxed model.
                    nested_result.set(Some(unsafe { dispatch(pointer.get()) }));
                }
            }
        })),
        nested_denials: 0,
    };
    let model = Box::into_raw(Box::new(model));
    pointer.set(model);

    // SAFETY: `model` remains allocated until both dispatches return.
    assert!(unsafe { dispatch(model) });
    assert_eq!(nested_result.get(), Some(false));
    assert_eq!(calls.get(), 1);
    // SAFETY: the first dispatch restored the responder to the live model.
    assert!(unsafe { dispatch(model) });
    assert_eq!(calls.get(), 2);

    // SAFETY: no dispatch is active and this pointer came from Box::into_raw.
    let model = unsafe { Box::from_raw(model) };
    assert_eq!(model.nested_denials, 1);
}
