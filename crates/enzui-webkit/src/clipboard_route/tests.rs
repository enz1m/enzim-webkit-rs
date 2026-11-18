//! Pure authorization tests for [`super`].
//!
//! These run in a build that links no WebKit. They cover the *decision* half
//! only; that a real page copy reaches the real `WPEClipboard`, and that host
//! text reaches the real focused DOM field, is proved by the feature-on
//! `wpe_clipboard_route` gate - a pure test cannot make that claim.

use super::*;
use crate::web::ViewRouter;

fn live_pair() -> (ViewRouter, ViewId) {
    let mut router = ViewRouter::new();
    let view = router.create(7);
    (router, view)
}

#[test]
fn copied_page_debug_redacts_text_through_the_outcome() {
    const SECRET_CANARY: &str = "PAGE_COPY_SECRET_CANARY_DO_NOT_LOG";
    let copy = PageCopy {
        text: SECRET_CANARY.to_owned(),
        change_count_before: 41,
        change_count_after: 42,
    };

    // Positive control: Debug redaction must not damage the public payload the
    // host writes to its functional clipboard.
    assert_eq!(copy.text.as_bytes(), SECRET_CANARY.as_bytes());

    let copy_debug = format!("{copy:?}");
    assert!(copy_debug.contains("PageCopy"), "{copy_debug}");
    assert!(copy_debug.contains("[redacted]"), "{copy_debug}");
    assert!(
        copy_debug.contains("change_count_before: 41"),
        "{copy_debug}"
    );
    assert!(
        copy_debug.contains("change_count_after: 42"),
        "{copy_debug}"
    );
    assert!(
        !copy_debug.contains(SECRET_CANARY),
        "PageCopy Debug leaked the clipboard canary: {copy_debug}"
    );

    let outcome = ClipboardOutcome::Copied(copy);
    let outcome_debug = format!("{outcome:?}");
    assert!(outcome_debug.contains("Copied"), "{outcome_debug}");
    assert!(outcome_debug.contains("[redacted]"), "{outcome_debug}");
    assert!(
        outcome_debug.contains("change_count_before: 41"),
        "{outcome_debug}"
    );
    assert!(
        outcome_debug.contains("change_count_after: 42"),
        "{outcome_debug}"
    );
    assert!(
        !outcome_debug.contains(SECRET_CANARY),
        "ClipboardOutcome::Copied Debug leaked the clipboard canary: {outcome_debug}"
    );
    let ClipboardOutcome::Copied(copy) = &outcome else {
        panic!("the positive-control outcome must stay Copied");
    };
    assert_eq!(copy.text.as_bytes(), SECRET_CANARY.as_bytes());
}

#[test]
fn a_superseded_generation_is_refused_before_the_gesture_is_considered() {
    let mut router = ViewRouter::new();
    let old = router.create(3);
    let _new = router.recreate(3);
    assert!(!router.accepts(old), "the old generation must be dead");
    assert_eq!(
        authorize(
            Some(old),
            router.accepts(old),
            old,
            ClipboardDirection::HostToPage,
            HostGesture::Absent,
            Some(MAX_CLIPBOARD_TEXT_BYTES + 1),
        ),
        Err(ClipboardRouteError::ViewNotLive { view: old }),
        "liveness is checked before the gesture and before the ceiling",
    );
}

#[test]
fn both_directions_require_a_host_user_gesture() {
    let (router, view) = live_pair();
    for (direction, payload) in [
        (ClipboardDirection::PageToHost, None),
        (ClipboardDirection::HostToPage, Some(8)),
    ] {
        assert_eq!(
            authorize(
                Some(view),
                router.accepts(view),
                view,
                direction,
                HostGesture::Absent,
                payload,
            ),
            Err(ClipboardRouteError::NoUserGesture { direction }),
            "{} must refuse without a host gesture",
            direction.label(),
        );
    }
}

#[test]
fn the_paste_ceiling_is_exact_and_a_copy_has_no_payload_to_bound() {
    let (router, view) = live_pair();
    let live = router.accepts(view);
    // Exactly at the ceiling: allowed.
    assert_eq!(
        authorize(
            Some(view),
            live,
            view,
            ClipboardDirection::HostToPage,
            HostGesture::Present,
            Some(MAX_CLIPBOARD_TEXT_BYTES),
        ),
        Ok(()),
        "a paste of exactly the ceiling must be allowed",
    );
    // One byte over: typed refusal naming both numbers.
    assert_eq!(
        authorize(
            Some(view),
            live,
            view,
            ClipboardDirection::HostToPage,
            HostGesture::Present,
            Some(MAX_CLIPBOARD_TEXT_BYTES + 1),
        ),
        Err(ClipboardRouteError::TextTooLarge {
            size: MAX_CLIPBOARD_TEXT_BYTES + 1,
            limit: MAX_CLIPBOARD_TEXT_BYTES,
        }),
    );
    // A copy carries no host payload, so an absurd size is not even offered.
    assert_eq!(
        authorize(
            Some(view),
            live,
            view,
            ClipboardDirection::PageToHost,
            HostGesture::Present,
            None,
        ),
        Ok(()),
    );
}
