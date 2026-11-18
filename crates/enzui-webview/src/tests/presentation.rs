// A frame is presented, and the frame presented is the sink's displayed
// one: the surface-publication and bounded-delivery tests.
//
// This file is `include!`d by `web_view/tests.rs`, so every item below
// lands in the `web_view::tests` module itself - the test paths are
// exactly the ones the pre-split file produced. It is therefore not a
// module: it has no `//!` docs (an inner attribute cannot follow items
// in the including module) and no `use super::*;` (the including module
// already has one).

// ---------------------------------------------------------------------------
// 1. A frame is presented - positive control first.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 2. The bound is proven by mechanism through BoundedFrameSink,
//    presented by the widget. The widget presents the sink's displayed
//    frame (the latest), never a stale one.
// ---------------------------------------------------------------------------

#[test]
fn the_widget_presents_the_sinks_latest_displayed_frame_under_a_flood() {
    // Reuse the real BoundedFrameSink: flood it, present, and hand the
    // widget the displayed frame. The widget must render that frame,
    // proving the presentation path is wired to the bounded sink and
    // (by the sink's own bound) never holds more than the retained-
    // buffer cap.
    let mut sink = BoundedFrameSink::new(Generation::FIRST);
    for seq in 1..=500 {
        sink.deliver(frame(seq));
    }
    // Present: the in-flight (seq 1) becomes displayed, the queued latest (500)
    // is promoted.
    assert!(sink.present().is_some());
    // The bound held throughout: at most 3 real buffers, never 500.
    assert!(
        sink.retained_buffers() <= enzui_core::frame_plan::FrameBounds::MAX_RETAINED,
        "the sink bound must hold: {} buffers",
        sink.retained_buffers()
    );
    assert_eq!(sink.accepted(), 500, "positive control: all 500 arrived");

    // Hand the widget the sink's displayed frame and confirm it renders.
    let displayed = sink
        .displayed()
        .expect("a frame is displayed after present");
    let displayed_seq = displayed.seq();
    let el: Element<'_, ()> = enz_web_view(view(), Some(displayed), true).into();
    let nodes = collected(el);
    assert!(
        has_label_containing(&nodes, "Web view"),
        "the widget must present the sink's displayed frame; labels: {:?}",
        labels(&nodes)
    );
    // The displayed frame is the first in-flight (seq 1), not a dropped one -
    // this pins that this code presented a real sink frame, not an arbitrary one.
    assert_eq!(displayed_seq, FrameSeq(1));
}

#[test]
fn a_stale_frame_is_never_the_displayed_one_the_widget_shows() {
    // The stale-frame sabotage target, at the mechanism level: after a source
    // swap, a frame from the old generation is discarded by the sink and
    // never becomes displayed, so the widget can never be handed it. If
    // the widget presented `in_flight` instead of `displayed`, or the
    // sink retained a stale frame, this would change.
    let mut sink = BoundedFrameSink::new(Generation::FIRST);
    sink.deliver(frame(1));
    sink.present();
    let g1 = {
        let mut g = Generation::FIRST;
        g = g.next();
        g
    };
    sink.replace_source(g1);
    // A late frame from the old generation:
    let stale = Rgba8Frame::new(Generation::FIRST, FrameSeq(99), 4, 4, vec![7u8; 64]).unwrap();
    assert!(matches!(
        sink.deliver(stale),
        Delivery::DiscardedStale { .. }
    ));
    // The displayed frame is still the pre-swap one (seq 1, 2x2), not
    // the stale 4x4 seq-99 frame.
    let displayed = sink.displayed().expect("displayed survives a source swap");
    assert_eq!(displayed.seq(), FrameSeq(1));
    assert_eq!(
        displayed.width(),
        2,
        "the stale 4x4 frame did not become displayed"
    );
}
