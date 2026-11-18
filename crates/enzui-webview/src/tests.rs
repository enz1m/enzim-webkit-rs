//! Tests for `EnzWebView`.

use super::*;
use enzui_core::collect::{CollectedNode, SemanticsCollector};
use enzui_core::frame_plan::FrameSeq;
use enzui_core::media::{BoundedFrameSink, Delivery, Generation, Rgba8Frame};
use enzui_core::semantics::Role;
use enzui_webkit::input::{InputEvent, KeyCode, PointerButton, ViewPoint};
use enzui_webkit::page_a11y::{AccessibleSource, PageA11y, PageLimits, PageNodeAddress, atspi};
use enzui_webkit::page_delivery::{PageA11yDelivery, PublishedPage};
use enzui_webkit::web::{ViewId, ViewRouter};
use iced::advanced::layout;
use iced::advanced::layout::Measure as _;
use iced::advanced::widget::{Operation, Tree};
use iced::{Element, Size};

// ---------------------------------------------------------------------------
// The test families.
//
// `ime_and_cursor` is a nested module. The `include!`s splice their
// items into this module, giving those tests bare
// `web_view::tests::<name>` paths. Order is irrelevant because every
// fragment is item-only.
// ---------------------------------------------------------------------------

mod ime_and_cursor;

include!("tests/presentation.rs");
include!("tests/surface_layout.rs");
include!("tests/page_a11y.rs");
include!("tests/page_actions.rs");
include!("tests/frame_handle.rs");

// ---------------------------------------------------------------------------
// Painted-extent probe for the loading placeholder.
//
// A fixed-height child inside a derived-height parent leaves most of
// the placeholder unpainted. Only a pixel check detects that; every
// builder field (`card_height`, the ratio, the cap) was individually
// correct, and a stored-height assertion is green either way. So this
// measures the vertical extent of skeleton ink against the
// placeholder's own laid-out box.
// ---------------------------------------------------------------------------

/// Lay `element` out into a `w` x `h` logical canvas, draw it, and return
/// `(rgba, root_bounds)`.
fn render(
    element: Element<'static, ()>,
    w: u32,
    h: u32,
) -> (Vec<u8>, iced::Rectangle, iced::Color) {
    use iced::advanced::renderer::Headless;

    let mut renderer = iced_test::futures::futures::executor::block_on(
        <iced_test::renderer::Renderer as Headless>::new(
            iced::advanced::renderer::Settings::default(),
            std::env::var("ICED_TEST_BACKEND").ok().as_deref(),
        ),
    )
    .expect("headless renderer");

    // The placeholder's own box: `UserInterface::build` lays the root
    // out. Use `Limits::new(ZERO, canvas)` so the same limits reproduce
    // the rectangle the draw pass uses. The ink extent below is quoted
    // against this, never against the canvas.
    let mut probe = element;
    let mut tree = Tree::new(probe.as_widget());
    // `Tree::new` does not populate children; the shimmer clock the skeleton
    // wraps itself in indexes `tree.children[0]` in `layout()`.
    probe.as_widget_mut().diff(&mut tree);
    let root = probe
        .as_widget_mut()
        .measure_snapshot(
            &mut tree,
            &renderer,
            &layout::Limits::new(Size::ZERO, Size::new(w as f32, h as f32)),
        )
        .bounds();

    let mut ui = iced_test::runtime::user_interface::UserInterface::build(
        probe,
        Size::new(w as f32, h as f32),
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );

    let theme = iced::Theme::Dark;
    let base = <iced::Theme as iced::advanced::graphics::core::theme::Base>::base(&theme);
    ui.draw(
        &mut renderer,
        &theme,
        &iced::advanced::renderer::Style {
            text_color: base.text_color,
        },
        iced::advanced::mouse::Cursor::Unavailable,
    );
    let px = renderer.screenshot(iced::Size::new(w, h), 1.0, base.background_color);
    (px, root, base.background_color)
}

/// Rows in `[y0, y1)` at column `x` whose pixel differs from `bg` by more than
/// a hair - i.e. rows the skeleton actually painted.
fn painted_rows(px: &[u8], w: u32, x: u32, y0: u32, y1: u32, bg: iced::Color) -> usize {
    let bg = (
        (bg.r * 255.0).round() as i32,
        (bg.g * 255.0).round() as i32,
        (bg.b * 255.0).round() as i32,
    );
    (y0..y1)
        .filter(|y| {
            let i = ((y * w + x) * 4) as usize;
            let (r, g, b) = (px[i] as i32, px[i + 1] as i32, px[i + 2] as i32);
            (r - bg.0).abs() + (g - bg.1).abs() + (b - bg.2).abs() > 6
        })
        .count()
}

type Renderer = iced_test::renderer::Renderer;

fn view() -> ViewId {
    ViewId::new(1)
}

/// Wrap a translated tree in the router-checked [`PublishedPage`] witness the
/// widget requires. A bare `PageA11y` is not accepted, so every publication is
/// proven to have passed a live-view check
/// - which is exactly the property the `stale_widget_publication` gate attacks.
fn published(view: ViewId, page: PageA11y) -> PublishedPage {
    let mut router = ViewRouter::new();
    let live = router.create(view.slot());
    assert_eq!(live, view, "test helper: created view must equal view()");
    let mut delivery = PageA11yDelivery::new();
    delivery.offer(&router, live, page);
    delivery
        .published_page(&router, live)
        .expect("a snapshot offered for the live view must publish")
}

/// A router whose live view for `view`'s slot is exactly `view`, satisfying the
/// widget's consumption-time [`ViewRouter::accepts`] check. Only the current,
/// live id is accepted.
fn live_router_for(view: ViewId) -> ViewRouter {
    let mut router = ViewRouter::new();
    let live = router.create(view.slot());
    assert_eq!(live, view, "test helper: created view must equal view()");
    router
}

/// A validated RGBA8 frame, small enough to be free.
fn frame(seq: u64) -> Rgba8Frame {
    Rgba8Frame::new(Generation::FIRST, FrameSeq(seq), 2, 2, vec![0u8; 16])
        .expect("a 2x2 frame with 16 bytes is valid")
}

/// Collect every semantics node the view publishes on a headless renderer.
fn collected(view: Element<'_, (), iced::Theme, Renderer>) -> Vec<CollectedNode> {
    let mut renderer = iced_test::futures::futures::executor::block_on(
        <Renderer as iced::advanced::renderer::Headless>::new(
            iced::advanced::renderer::Settings::default(),
            std::env::var("ICED_TEST_BACKEND").ok().as_deref(),
        ),
    )
    .expect("headless renderer");
    let mut ui = iced_test::runtime::user_interface::UserInterface::build(
        view,
        Size::new(1400.0, 900.0),
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    let mut collector = SemanticsCollector::new();
    ui.operate(&renderer, &mut collector as &mut dyn Operation);
    collector.into_collected()
}

fn labels(nodes: &[CollectedNode]) -> Vec<String> {
    nodes
        .iter()
        .filter_map(|n| n.semantics.label.clone())
        .collect()
}

fn has_label_containing(nodes: &[CollectedNode], needle: &str) -> bool {
    labels(nodes).iter().any(|l| l.contains(needle))
}
