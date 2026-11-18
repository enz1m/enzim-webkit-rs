//! Route-level wiring: the real `webview` route drives the protocol - every test
//! feeds a real `Message` in and reads the rendered tree back.

use crate::*;
use enzui_core::collect::{CollectedNode, SemanticsCollector};
use iced::advanced::widget::Operation;
use iced::{Element, Size};
use iced_test::runtime::user_interface::{Cache, UserInterface};

type Renderer = iced_test::renderer::Renderer;

/// Lay out the real route and collect every published semantics node.
fn collect_route(app: &App) -> Vec<CollectedNode> {
    let view: Element<'_, Message, iced::Theme, Renderer> = app.view();
    let mut renderer = iced_test::futures::futures::executor::block_on(
        <Renderer as iced::advanced::renderer::Headless>::new(
            iced::advanced::renderer::Settings::default(),
            std::env::var("ICED_TEST_BACKEND").ok().as_deref(),
        ),
    )
    .expect("headless renderer");
    let mut ui = UserInterface::build(
        view,
        Size::new(1400.0, 900.0),
        Cache::default(),
        &mut renderer,
    );
    let mut collector = SemanticsCollector::new();
    ui.operate(&renderer, &mut collector as &mut dyn Operation);
    collector.into_collected()
}

/// Every collected label text, in tree order.
fn all_labels(nodes: &[CollectedNode]) -> Vec<String> {
    nodes
        .iter()
        .filter_map(|n| n.semantics.label.clone())
        .collect()
}

/// Whether any label in the collected tree contains `needle`.
fn has_label_containing(nodes: &[CollectedNode], needle: &str) -> bool {
    all_labels(nodes).iter().any(|l| l.contains(needle))
}

fn fresh_app() -> App {
    App::new(enzui_theme::EnzTheme::dark())
}

// 1. Route renders with the real protocol types.

// 2. Policy wiring: bad scheme renders Deny.

// 3. Focus wiring: Tab forwarding and stale-answer discard.

// 4. Frame wiring: offer and stale-generation discard.

// 5. Profile isolation wiring.

// 6. EnzWebView surface + input path: severed-wiring sabotage reddens here
// while widget tests stay green (island proof).

#[test]
fn an_enz_web_view_input_event_crosses_the_app_owned_update_hop() {
    use enzui_webkit::input::{InputEvent, Modifiers, ViewPoint};

    let mut app = fresh_app();
    let live = app.webview.borrow().live_view.expect("initial live view");
    let _ = app.update(Message::WebViewInput(InputEvent::PointerMoved {
        view: live,
        at: ViewPoint { x: 17.0, y: 29.0 },
        modifiers: Modifiers::NONE,
    }));
    let nodes = collect_route(&app);
    assert!(
        has_label_containing(&nodes, "widget input")
            && has_label_containing(&nodes, "x: 17.0")
            && has_label_containing(&nodes, "y: 29.0"),
        "the widget event must cross Message::WebViewInput and be rendered by the app-owned model; labels: {:?}",
        all_labels(&nodes)
    );
}

#[test]
fn a_stale_widget_input_is_refused_before_native_dispatch() {
    use enzui_webkit::input::{InputEvent, Modifiers, ViewPoint};

    let mut app = fresh_app();
    let dead = app.webview.borrow().live_view.expect("initial live view");
    let _ = app.update(Message::WebViewRecreate);
    let _ = app.update(Message::WebViewInput(InputEvent::PointerMoved {
        view: dead,
        at: ViewPoint { x: 1.0, y: 2.0 },
        modifiers: Modifiers::NONE,
    }));
    let nodes = collect_route(&app);
    assert!(
        has_label_containing(&nodes, "stale widget input refused"),
        "an input carrying the dead generation must stop at the app-owned model; labels: {:?}",
        all_labels(&nodes)
    );
}

// Page a11y contract: unit tests pass with the route wired to nothing - these
// fail when the route stops handing the page tree to the widget.

// Live a11y: delivery tests are pure and pass unwired - these drive real
// messages and read the rendered route.

/// Feed one real message through the app's real update path.
fn send(app: &mut App, message: Message) {
    let _ = app.update(message);
}

#[test]
fn an_activation_after_a_crash_is_refused_rather_than_reaching_a_dead_page() {
    // Dead-page actions refuse: `DoAction` must never reach a dead WebProcess
    // address.
    let mut app = fresh_app();
    // Calibrate on publication: the log keeps history, so a pre-crash activation
    // would leave a legitimate line behind.
    let nodes = collect_route(&app);
    assert!(
        has_label_containing(&nodes, "Demo Page Button"),
        "calibration: the button is published before the crash: {:?}",
        all_labels(&nodes)
    );

    send(&mut app, Message::WebViewRecreate);
    send(&mut app, Message::WebViewActivatePageButton);
    let labels = all_labels(&collect_route(&app));
    assert!(
        labels
            .iter()
            .any(|l| l.contains("no page published; nothing activated")),
        "an activation after a crash must be refused; labels: {labels:?}"
    );
    // Any such line is a real leak, not log history.
    assert!(
        !labels.iter().any(|l| l.contains("activated obj:")),
        "the route must not report a successful activation into a dead page: {labels:?}"
    );
}

// PRODUCTION OS-AT route: AccessKit Click through dispatch to update.
// Demo-button tests prove the service, not the AT path.

// IME/cursor contract: reads `State::Updated` for the whole route - severed
// wiring fails here while the widget suite stays green.

use iced::advanced::mouse;

/// Pointer inside the presented surface (laid out below the route chrome at
/// 1400x900).
fn over_the_surface() -> mouse::Cursor {
    mouse::Cursor::Available(iced::Point::new(200.0, 430.0))
}

#[test]
fn real_widget_tab_and_shift_tab_enter_the_focus_handoff_before_toolkit_traversal() {
    use iced::advanced::graphics::core::shell::Waker;
    use iced::advanced::graphics::core::window::Headless as HeadlessWindow;

    let mut app = fresh_app();
    send(&mut app, Message::WebViewOfferFrame);
    send(&mut app, Message::WebViewPresentFrame);
    let routed = {
        let view: Element<'_, Message, iced::Theme, Renderer> = app.view();
        let mut renderer = iced_test::futures::futures::executor::block_on(
            <Renderer as iced::advanced::renderer::Headless>::new(
                iced::advanced::renderer::Settings::default(),
                None,
            ),
        )
        .expect("headless renderer");
        let mut ui = UserInterface::build(
            view,
            Size::new(1400.0, 900.0),
            Cache::default(),
            &mut renderer,
        );
        let key = |modifiers: iced::keyboard::Modifiers| {
            let tab = iced::keyboard::Key::Named(iced::keyboard::key::Named::Tab);
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: tab.clone(),
                modified_key: tab,
                physical_key: iced::keyboard::key::Physical::Unidentified(
                    iced::keyboard::key::NativeCode::Unidentified,
                ),
                location: iced::keyboard::Location::Standard,
                modifiers,
                text: None,
                repeat: false,
            })
        };
        let now = iced::time::Instant::now();
        let events = [
            // Identical-layout redraws: one integer viewport report, not one
            // message per frame.
            iced::Event::Window(iced::window::Event::RedrawRequested(now)),
            iced::Event::Window(iced::window::Event::RedrawRequested(now)),
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left)),
            key(iced::keyboard::Modifiers::empty()),
            key(iced::keyboard::Modifiers::SHIFT),
        ];
        let mut messages = iced::advanced::shell::Bus::new();
        let _ = ui.update(
            &HeadlessWindow,
            &Waker::noop(),
            &events,
            over_the_surface(),
            &mut renderer,
            &mut messages,
        );
        messages
    };
    let routed_inputs = routed
        .iter()
        .filter(|message| matches!(message, Message::WebViewInput(_)))
        .count();
    assert!(
        routed_inputs >= 4,
        "the decisive path must originate in EnzWebView (focus, press, two Tabs): {routed:?}"
    );
    let viewport_sizes: Vec<_> = routed
        .iter()
        .filter_map(|message| match message {
            Message::WebViewViewportResize(view, size) => Some((*view, *size)),
            _ => None,
        })
        .collect();
    assert_eq!(
        viewport_sizes.len(),
        1,
        "two redraws at one real EnzWebView allocation must emit exactly one viewport resize: {routed:?}"
    );
    let (viewport_view, viewport_size) = viewport_sizes[0];
    assert_eq!(Some(viewport_view), app.webview.borrow().live_view);
    assert!(viewport_size.width() > 0 && viewport_size.height() > 0);
    for message in routed {
        let _ = app.update(message);
    }
    assert_eq!(
        app.webview.borrow().native_viewport,
        Some(viewport_size),
        "the widget's measured bounds did not cross the app-owned route"
    );
    assert!(
        app.webview
            .borrow()
            .last_focus_outcome
            .as_deref()
            .is_some_and(|outcome| outcome.contains("Previous")),
        "the second real Shift+Tab must release backward through FocusHandoff"
    );
}

#[test]
fn secure_ime_text_is_redacted_from_retained_and_rendered_probe_diagnostics() {
    const SENTINEL: &str = "ime-secret-2858-に🔒";
    let mut app = fresh_app();
    send(&mut app, Message::WebViewFocusGained);
    send(&mut app, Message::WebViewFocusPasswordInput);
    app.webview.borrow_mut().page_preedit(SENTINEL);

    {
        let service = app.webview.borrow();
        let published = service.published_ime().expect("secure IME published");
        assert_eq!(
            published.input().purpose,
            enzui_webkit::web::Purpose::Secure
        );
        assert_eq!(
            published
                .preedit()
                .map(|preedit| preedit.content.as_bytes()),
            Some(SENTINEL.as_bytes()),
            "probe forwarding must retain the exact preedit bytes"
        );
        let status = service
            .last_ime
            .as_deref()
            .expect("retained preedit status");
        assert!(!status.contains(SENTINEL));
        assert!(status.contains(enzui_webkit::web::IME_TEXT_REDACTION));
    }

    let preedit_nodes = collect_route(&app);
    let preedit_labels = all_labels(&preedit_nodes);
    assert!(
        !preedit_labels.iter().any(|label| label.contains(SENTINEL)),
        "rendered preedit exposed the secure sentinel: {preedit_labels:?}"
    );
    assert!(
        preedit_labels.iter().any(|label| {
            label.contains(enzui_webkit::web::IME_TEXT_REDACTION) && label.contains("Secure")
        }),
        "rendered preedit must retain secure purpose and show the marker: {preedit_labels:?}"
    );

    send(
        &mut app,
        Message::WebViewImeEvent(enzui_webkit::web::ToolkitImeEvent::Preedit(
            SENTINEL.to_owned(),
            Some(4..13),
        )),
    );
    {
        let service = app.webview.borrow();
        assert_eq!(
            service.last_ime_effect,
            Some(enzui_webkit::ime_bridge::ImeEffect::SetPreedit {
                text: SENTINEL.to_owned(),
                caret: Some(13),
            }),
            "routed preedit must retain exact text and byte caret for the page"
        );
        let status = service.last_ime.as_deref().expect("retained routed status");
        assert!(!status.contains(SENTINEL));
        assert!(status.contains("Preedit"));
        assert!(status.contains("4..13"));
        assert!(status.contains(enzui_webkit::web::IME_TEXT_REDACTION));
    }

    send(
        &mut app,
        Message::WebViewImeEvent(enzui_webkit::web::ToolkitImeEvent::Commit(
            SENTINEL.to_owned(),
        )),
    );
    {
        let service = app.webview.borrow();
        assert_eq!(
            service.last_ime_effect,
            Some(enzui_webkit::ime_bridge::ImeEffect::Commit(
                SENTINEL.to_owned()
            )),
            "routed commit must retain exact text for the page"
        );
        let status = service.last_ime.as_deref().expect("retained commit status");
        assert!(!status.contains(SENTINEL));
        assert!(status.contains("Commit"));
        assert!(status.contains(enzui_webkit::web::IME_TEXT_REDACTION));
    }

    let committed_nodes = collect_route(&app);
    let committed_labels = all_labels(&committed_nodes);
    assert!(
        !committed_labels
            .iter()
            .any(|label| label.contains(SENTINEL)),
        "rendered commit exposed the secure sentinel: {committed_labels:?}"
    );
    assert!(
        committed_labels.iter().any(|label| {
            label.contains("Commit") && label.contains(enzui_webkit::web::IME_TEXT_REDACTION)
        }),
        "rendered commit must preserve its variant and show the marker: {committed_labels:?}"
    );
}

#[test]
fn browser_window_submits_addresses_before_renderer_readiness() {
    let mut app = fresh_app();
    app.browser_mode = true;
    send(
        &mut app,
        Message::BrowserAddress("  example.com/path  ".into()),
    );
    send(&mut app, Message::BrowserGo);
    assert_eq!(app.address, "https://example.com/path");
    assert!(matches!(
        app.pending_navigation.as_ref(),
        Some(crate::webview_native::BrowserAction::Navigate(url)) if url == "https://example.com/path"
    ));
    assert!(app.pending_native_open);
}
