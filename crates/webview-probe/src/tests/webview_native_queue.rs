//! Clipboard outcomes survive native-queue pressure: displaced `Refused` answers
//! leave stale previous outcomes on screen (refusals read as completed copies).
//! Driven under real `push_bounded` pressure past `UPDATE_CAP` - with eviction
//! really happening (ordinaries dropped, queue bounded) - never predicate-only.
//! Old tab-only predicates redden both clipboard tests.

use std::collections::VecDeque;

use enzui_webkit::web::ViewId;
use enzui_webkit::{ClipboardOutcome, HostPaste};

use crate::webview_native::{NativeUpdate, UPDATE_CAP, push_bounded};

/// Superseded-per-frame ordinaries: the displaceable class.
fn ordinary(view: ViewId, tag: &str) -> NativeUpdate {
    NativeUpdate {
        view,
        report: None,
        metadata: Some(std::sync::Arc::new(crate::webview_native::NativeMetadata {
            cursor: Some(tag.to_owned()),
            ..Default::default()
        })),
        frame: None,
        gpu_frame: None,
        tab_reply: None,
        clipboard: None,
        view_focused: Some(true),
        error: None,
    }
}

/// Clipboard-carrying updates: the undisplaceable class.
fn with_clipboard(view: ViewId, outcome: ClipboardOutcome) -> NativeUpdate {
    NativeUpdate {
        clipboard: Some(outcome),
        ..ordinary(view, "clipboard")
    }
}

fn clipboards(queue: &VecDeque<NativeUpdate>) -> Vec<&ClipboardOutcome> {
    queue.iter().filter_map(|u| u.clipboard.as_ref()).collect()
}

#[test]
fn a_clipboard_outcome_survives_a_flood_of_ordinary_updates() {
    let view = ViewId::new(1);
    let mut queue: VecDeque<NativeUpdate> = VecDeque::new();

    // Flood-survival: answers persist through 4×-cap ordinary traffic AND drain -
    // with eviction proven (oldest ordinary gone, cap held).
    for i in 0..UPDATE_CAP {
        push_bounded(&mut queue, ordinary(view, &format!("pre-{i}")));
    }
    assert_eq!(queue.len(), UPDATE_CAP, "the queue must start saturated");

    // Host paste into the full queue.
    let answer = ClipboardOutcome::Pasted(HostPaste {
        bytes: 11,
        change_count: 7,
    });
    push_bounded(&mut queue, with_clipboard(view, answer.clone()));

    // Pages keep framing past the cap.
    for i in 0..(UPDATE_CAP * 4) {
        push_bounded(&mut queue, ordinary(view, &format!("post-{i}")));
        assert!(
            queue.len() <= UPDATE_CAP,
            "the queue must stay bounded at {UPDATE_CAP}, saw {}",
            queue.len(),
        );
    }

    // Eviction proven: cap held, oldest ordinary displaced - unbounded queues
    // can't satisfy this.
    assert_eq!(queue.len(), UPDATE_CAP, "eviction must have occurred");
    assert!(
        !queue.iter().any(|u| u
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.cursor.as_deref())
            == Some("pre-0")),
        "the oldest ordinary update must have been displaced",
    );

    // Decisive: THE produced answer still queued.
    assert_eq!(
        clipboards(&queue),
        vec![&answer],
        "the clipboard answer must survive ordinary-update pressure; a dropped \
         outcome leaves the host reporting the PREVIOUS copy/paste result",
    );

    // Survival useful only if hosts read it.
    let drained: Vec<NativeUpdate> = queue.drain(..).collect();
    let seen: Vec<&ClipboardOutcome> = drained
        .iter()
        .filter_map(|u| u.clipboard.as_ref())
        .collect();
    assert_eq!(seen, vec![&answer], "the answer must reach the drain");
}

#[test]
fn a_queue_of_nothing_but_answers_stays_bounded() {
    // All-answer floods stay bounded (oldest displaced, newest survive):
    // protection can't be absolute or queues unbound - the sole dropping
    // circumstance.
    let view = ViewId::new(4);
    let mut queue: VecDeque<NativeUpdate> = VecDeque::new();
    for i in 0..(UPDATE_CAP * 2) {
        let outcome = ClipboardOutcome::Pasted(HostPaste {
            bytes: i,
            change_count: i as i64,
        });
        push_bounded(&mut queue, with_clipboard(view, outcome));
        assert!(
            queue.len() <= UPDATE_CAP,
            "an all-answer queue must still be bounded",
        );
    }
    assert_eq!(queue.len(), UPDATE_CAP);
    // Newest survive, oldest displaced, in order.
    let first = queue
        .front()
        .and_then(|u| u.clipboard.as_ref())
        .expect("every entry carries an answer");
    assert_eq!(
        *first,
        ClipboardOutcome::Pasted(HostPaste {
            bytes: UPDATE_CAP,
            change_count: UPDATE_CAP as i64,
        }),
        "the oldest answers are the ones displaced under an all-answer flood",
    );
}
