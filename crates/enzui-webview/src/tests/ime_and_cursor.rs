//! IME and cursor routing: the page's caret reaches iced's window input
//! method, and the page's cursor reaches iced's `mouse_interaction`.
//!
//! Driven through the widget's REAL `update`/`mouse_interaction`, reading
//! `Shell::input_method()` - the value the runtime actually consumes. A test
//! that called `window_ime_rect` alone would prove the arithmetic and nothing
//! about routing, which is the island defect the parent module's header warns
//! about.
//!
//! This file is a real nested test module. It also contains the routed
//! pointer, touch, keyboard, and grab tests that share this module's `Recorder`
//! widget and `routed_*` fixtures.

use super::*;
use enzui_webkit::web::{CaretRect, PageIme, PageInput, Purpose};
use iced::advanced::graphics::core::shell::Waker;
use iced::advanced::graphics::core::window::Headless as HeadlessWindow;
use iced::advanced::input_method::InputMethod;
use iced::advanced::{Layout, Shell, mouse, renderer};
use iced::{Color, Point, Rectangle};

/// The surface's laid-out box in these tests. 800x600 at the default cap.
const CANVAS: Size = Size::new(800.0, 600.0);

/// A live page IME open for `view` at `caret` (logical view pixels).
fn open_ime(
    router: &ViewRouter,
    view: ViewId,
    caret: (f32, f32, f32, f32),
    purpose: Purpose,
) -> PageIme {
    let mut ime = PageIme::new();
    let rect = CaretRect::new(caret.0, caret.1, caret.2, caret.3).expect("finite caret");
    let outcome = ime.claim(router, view, PageInput::new(rect, purpose));
    assert!(
        matches!(outcome, enzui_webkit::web::ImeClaim::Opened { .. }),
        "test setup: the IME must open, got {outcome:?}"
    );
    ime
}

/// Drive one real runtime frame through the widget and return what it asked
/// the window's input method for, plus any messages it published.
fn frame_input_method_captured<Message: 'static + std::fmt::Debug>(
    element: Element<'_, Message, iced::Theme, Renderer>,
    event: &iced::Event,
    cursor: mouse::Cursor,
    viewport: Rectangle,
) -> (InputMethod, Vec<Message>, bool) {
    let mut renderer = iced_test::futures::futures::executor::block_on(
        <Renderer as iced::advanced::renderer::Headless>::new(
            iced::advanced::renderer::Settings::default(),
            None,
        ),
    )
    .expect("headless renderer");
    let mut element = element;
    let mut tree = Tree::new(&element);
    element.as_widget_mut().diff(&mut tree);
    let limits = layout::Limits::new(Size::ZERO, CANVAS);
    let node = element
        .as_widget_mut()
        .measure_snapshot(&mut tree, &renderer, &limits);
    let layout = Layout::of(&node);
    let full = Rectangle::new(Point::ORIGIN, CANVAS);
    element.as_widget().draw(
        &tree,
        &mut renderer,
        &iced::Theme::Dark,
        &renderer::Style {
            text_color: Color::WHITE,
        },
        layout,
        cursor,
        &full,
    );
    let mut messages = iced::advanced::shell::Bus::<Message>::new();
    let mut shell = Shell::new(&HeadlessWindow, Waker::noop(), &mut messages);
    element.as_widget_mut().update(
        &mut tree, event, layout, cursor, &renderer, &mut shell, &viewport,
    );
    let captured = shell.is_event_captured();
    (
        shell.input_method().clone(),
        messages.into_iter().collect(),
        captured,
    )
}

/// The same frame, without the capture flag, for the tests that only care
/// about what was published.
fn frame_input_method<Message: 'static + std::fmt::Debug>(
    element: Element<'_, Message, iced::Theme, Renderer>,
    event: &iced::Event,
    cursor: mouse::Cursor,
    viewport: Rectangle,
) -> (InputMethod, Vec<Message>) {
    let (ime, messages, _) = frame_input_method_captured(element, event, cursor, viewport);
    (ime, messages)
}

fn redraw() -> iced::Event {
    iced::Event::Window(iced::window::Event::RedrawRequested(
        std::time::Instant::now(),
    ))
}

#[test]
fn a_password_field_asks_the_window_for_a_secure_input_method() {
    let router = live_router_for(view());
    let ime = open_ime(&router, view(), (10.0, 20.0, 2.0, 30.0), Purpose::Secure);
    let published = ime.published(&router, view()).expect("open");
    let f = frame(1);
    let el: Element<'_, ()> = enz_web_view(view(), Some(&f), true)
        .input_method(&published, &router)
        .into();
    let (asked, _) = frame_input_method(
        el,
        &redraw(),
        mouse::Cursor::Unavailable,
        Rectangle::new(Point::ORIGIN, CANVAS),
    );
    match asked {
        InputMethod::Enabled { purpose, .. } => assert_eq!(
            purpose,
            convert::purpose(Purpose::Secure),
            "a password field must reach the window as Secure"
        ),
        InputMethod::Disabled => panic!("nothing was published for a password field"),
    }
}

// -- real widget input routing ----------------------------------------

fn key_press(key: iced::keyboard::Key) -> iced::Event {
    iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
        modified_key: key.clone(),
        key,
        physical_key: iced::keyboard::key::Physical::Unidentified(
            iced::keyboard::key::NativeCode::Unidentified,
        ),
        location: iced::keyboard::Location::Standard,
        modifiers: iced::keyboard::Modifiers::default(),
        text: None,
        repeat: false,
    })
}

/// Drive multiple events through one retained widget tree. This is needed
/// for the focus contract: the pointer press and following key must observe
/// the same `WebViewState`, just as they do in a running iced application.
fn routed_element(
    routed_view: ViewId,
    visible: bool,
    padded: bool,
) -> Element<'static, InputEvent> {
    let inner: Element<'static, InputEvent> = enz_web_view_owned(routed_view, frame(1), visible)
        .on_input(|event| event)
        .into();
    if padded {
        iced::widget::container(inner)
            .padding(iced::Padding::new(40.0))
            .into()
    } else {
        inner
    }
}

/// Rebuild and diff the widget before every event while retaining one
/// `Tree`, matching iced's real view/update lifecycle.
fn routed_rebuild_sequence(
    steps: &[(ViewId, bool, iced::Event, mouse::Cursor)],
    padded: bool,
) -> (Vec<InputEvent>, Vec<bool>) {
    routed_rebuild_sequence_with_viewport(steps, padded, |_| Rectangle::new(Point::ORIGIN, CANVAS))
}

fn routed_rebuild_sequence_with_viewport(
    steps: &[(ViewId, bool, iced::Event, mouse::Cursor)],
    padded: bool,
    viewport_at: impl Fn(usize) -> Rectangle,
) -> (Vec<InputEvent>, Vec<bool>) {
    let renderer = iced_test::futures::futures::executor::block_on(
        <Renderer as iced::advanced::renderer::Headless>::new(
            iced::advanced::renderer::Settings::default(),
            None,
        ),
    )
    .expect("headless renderer");
    let mut initial = routed_element(steps[0].0, steps[0].1, padded);
    let mut tree = Tree::new(&initial);
    initial.as_widget_mut().diff(&mut tree);
    let mut messages = iced::advanced::shell::Bus::new();
    let mut captured = Vec::new();
    for (index, (routed_view, visible, event, cursor)) in steps.iter().enumerate() {
        let viewport = viewport_at(index);
        let mut element = routed_element(*routed_view, *visible, padded);
        tree.diff(&mut element);
        let node = element.as_widget_mut().measure_snapshot(
            &mut tree,
            &renderer,
            &layout::Limits::new(Size::ZERO, CANVAS),
        );
        let mut shell = Shell::new(&HeadlessWindow, Waker::noop(), &mut messages);
        element.as_widget_mut().update(
            &mut tree,
            event,
            Layout::of(&node),
            *cursor,
            &renderer,
            &mut shell,
            &viewport,
        );
        captured.push(shell.is_event_captured());
    }
    (messages.into_iter().collect(), captured)
}

fn routed_sequence(
    events: &[(iced::Event, mouse::Cursor)],
    padded: bool,
) -> (Vec<InputEvent>, Vec<bool>) {
    let steps = events
        .iter()
        .map(|(event, cursor)| (view(), true, event.clone(), *cursor))
        .collect::<Vec<_>>();
    routed_rebuild_sequence(&steps, padded)
}

#[test]
fn iced_pointer_events_use_the_widgets_real_padded_bounds() {
    // The padding gives the web surface a non-zero horizontal window
    // origin. (The fill-height aspect surface remains rooted at y=0 in
    // this container.) A helper fed guessed (0,0) bounds would report
    // x=55; the real widget route must subtract the laid-out x=40 origin.
    let at = Point::new(55.0, 70.0);
    let events = [(
        iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
        mouse::Cursor::Available(at),
    )];
    let (messages, captured) = routed_sequence(&events, true);
    assert_eq!(captured, vec![true], "a page-owned press must be captured");
    assert_eq!(messages.len(), 2);
    assert!(matches!(messages[0], InputEvent::FocusGained { .. }));
    assert_eq!(
        messages[1].view_point(),
        Some(ViewPoint { x: 15.0, y: 70.0 }),
        "the actual laid-out origin, not caller-supplied geometry, translates the press"
    );
    assert!(matches!(
        messages[1],
        InputEvent::PointerPressed {
            button: PointerButton::Primary,
            ..
        }
    ));
}

#[test]
fn keyboard_is_forwarded_only_after_the_web_area_takes_focus() {
    let key = key_press(iced::keyboard::Key::Character("q".into()));
    // Negative control: an unfocused web area must not steal a key from a
    // sibling text field.
    let (unfocused, uncaptured) =
        routed_sequence(&[(key.clone(), mouse::Cursor::Unavailable)], false);
    assert!(unfocused.is_empty());
    assert_eq!(uncaptured, vec![false]);

    let press = iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left));
    let (focused, captured) = routed_sequence(
        &[
            (press, mouse::Cursor::Available(Point::new(10.0, 10.0))),
            (key, mouse::Cursor::Unavailable),
        ],
        false,
    );
    assert_eq!(focused.len(), 3, "focus, press and key must reach the host");
    assert!(matches!(
        &focused[2],
        InputEvent::KeyPressed {
            key: KeyCode::Character(text),
            ..
        } if text == "q"
    ));
    assert_eq!(captured, vec![true, true]);
}

// -- the page's cursor -------------------------------------------------

// ------------------------------------------------------------------
// Pointer and touch capture: implicit pointer/touch capture, touch
// cancel, modifier propagation, extended named keys. Every gate is
// driven by multiple events through the same retained widget tree,
// because the properties under test are per-tree state (grabs, modifier
// latch) that a one-event probe cannot see.
// ------------------------------------------------------------------

/// A pointer press+release sequence on the same retained widget: the
/// release lands outside the widget's bounds. Without the implicit
/// grab, the release must be delivered; otherwise the release is
/// dropped and WebKit sees a down with no matching up.
#[test]
fn a_press_inside_and_release_outside_delivers_a_paired_release() {
    let inside = Point::new(20.0, 20.0);
    let outside = Point::new(-100.0, 20.0); // far left of the widget
    let events = [
        (
            iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
            mouse::Cursor::Available(inside),
        ),
        (
            iced::Event::Mouse(mouse::Event::CursorMoved {
                position: Point::new(-50.0, 20.0),
            }),
            mouse::Cursor::Available(Point::new(-50.0, 20.0)),
        ),
        (
            iced::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)),
            mouse::Cursor::Available(outside),
        ),
    ];
    let (messages, captured) = routed_sequence(&events, false);

    // Every event must reach the page and every one must be captured -
    // the drag belongs to the widget from press to release.
    assert_eq!(
        messages.len(),
        5,
        "focus + press + drag-out + outside release + leave must all reach the page; got {messages:?}"
    );
    assert_eq!(captured, vec![true, true, true]);
    assert!(matches!(messages[0], InputEvent::FocusGained { .. }));

    // The middle event is a drag-out move at the translated outside
    // point (view-relative: (-50, 20) - (0, 0) = (-50, 20)).
    match &messages[2] {
        InputEvent::PointerMoved { at, modifiers, .. } => {
            assert_eq!(at.x, -50.0);
            assert_eq!(at.y, 20.0);
            assert!(modifiers.button1(), "drag move must report button 1 held");
        }
        other => panic!("expected grabbed pointer move outside bounds, got {other:?}"),
    }
    // The release is paired with the press (Left) and carries the
    // translated outside point verbatim (no clip).
    match &messages[3] {
        InputEvent::PointerReleased {
            at,
            button,
            modifiers,
            ..
        } => {
            assert_eq!(*button, PointerButton::Primary);
            assert_eq!(at.x, -100.0);
            assert_eq!(at.y, 20.0);
            assert!(!modifiers.button1(), "button 1 must be clear on release");
        }
        other => panic!("expected grabbed pointer release outside bounds, got {other:?}"),
    }
    // The drag kept hover through the grab; ending it outside leaves once.
    assert!(matches!(messages[4], InputEvent::PointerLeft { .. }));
}

#[test]
fn hide_rebuild_terminally_cancels_touch_and_does_not_resume_the_grab() {
    let finger = iced::touch::Finger(8);
    let press = iced::Event::Touch(iced::touch::Event::FingerPressed {
        id: finger,
        position: Point::new(10.0, 10.0),
    });
    let redraw = iced::Event::Window(iced::window::Event::RedrawRequested(
        iced::time::Instant::now(),
    ));
    let lift = iced::Event::Touch(iced::touch::Event::FingerLifted {
        id: finger,
        position: Point::new(-50.0, 10.0),
    });
    let steps = [
        (view(), true, press, mouse::Cursor::Unavailable),
        (view(), false, redraw, mouse::Cursor::Unavailable),
        (view(), true, lift, mouse::Cursor::Unavailable),
    ];
    let (messages, captured) = routed_rebuild_sequence(&steps, false);
    assert_eq!(captured, vec![true, false, false]);
    assert_eq!(
        messages.len(),
        4,
        "hide must cancel touch and focus exactly once: {messages:?}"
    );
    assert!(matches!(messages[0], InputEvent::FocusGained { .. }));
    assert!(matches!(messages[1], InputEvent::TouchDown { seq: 8, .. }));
    assert!(matches!(
        messages[2],
        InputEvent::TouchCancel { seq: 8, .. }
    ));
    assert!(matches!(messages[3], InputEvent::FocusLost { .. }));
}

#[test]
fn window_reactivation_cannot_revive_hidden_or_replaced_page_ownership() {
    let mut router = ViewRouter::new();
    let old = router.create(63);
    let replacement = router.recreate(63);
    for (after, after_visible) in [(old, false), (replacement, true)] {
        let steps = [
            (
                old,
                true,
                iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
                mouse::Cursor::Available(Point::new(10.0, 10.0)),
            ),
            (
                old,
                true,
                iced::Event::Window(iced::window::Event::Unfocused),
                mouse::Cursor::Unavailable,
            ),
            (after, after_visible, redraw(), mouse::Cursor::Unavailable),
            (
                after,
                true,
                iced::Event::Window(iced::window::Event::Focused),
                mouse::Cursor::Unavailable,
            ),
            (
                after,
                true,
                key_press(iced::keyboard::Key::Character("forbidden".into())),
                mouse::Cursor::Unavailable,
            ),
        ];
        let (messages, captured) = routed_rebuild_sequence(&steps, false);
        assert_eq!(captured, [true, false, false, false, false], "{messages:?}");
        // Unfocusing the window keeps hover; hiding or replacing the view ends it.
        assert_eq!(messages.len(), 5, "{messages:?}");
        assert!(messages.iter().all(|event| event.view() == old));
        assert!(matches!(messages[3], InputEvent::FocusLost { .. }));
        assert!(matches!(messages[4], InputEvent::PointerLeft { .. }));
    }
    let steps = [
        (
            old,
            true,
            iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
            mouse::Cursor::Available(Point::new(10.0, 10.0)),
        ),
        (
            old,
            true,
            iced::Event::Window(iced::window::Event::Unfocused),
            mouse::Cursor::Unavailable,
        ),
        (
            old,
            true,
            iced::Event::Window(iced::window::Event::Focused),
            mouse::Cursor::Unavailable,
        ),
        (
            old,
            true,
            key_press(iced::keyboard::Key::Character("clipped".into())),
            mouse::Cursor::Unavailable,
        ),
    ];
    let (messages, captured) =
        routed_rebuild_sequence_with_viewport(&steps, false, |index| Rectangle {
            x: if index == 2 { 900.0 } else { 0.0 },
            y: 0.0,
            width: CANVAS.width,
            height: CANVAS.height,
        });
    assert_eq!(
        messages.len(),
        4,
        "a clipped page must not restore focus: {messages:?}"
    );
    assert_eq!(captured, [true, false, false, false]);
    let (messages, captured) = routed_sequence(
        &[
            (
                iced::Event::Window(iced::window::Event::Focused),
                mouse::Cursor::Unavailable,
            ),
            (
                key_press(iced::keyboard::Key::Character("unowned".into())),
                mouse::Cursor::Unavailable,
            ),
        ],
        false,
    );
    assert!(messages.is_empty());
    assert_eq!(captured, [false, false]);
}
