//! Production `WebViewClose` revokes the live page and frees every owner,
//! checked through `App::update` with seeded RGBA, policy, a11y, IME and focus
//! controls.

#[cfg(not(feature = "wpe"))]
use crate::*;
#[cfg(not(feature = "wpe"))]
use enzui_core::collect::{CollectedNode, SemanticsCollector};
#[cfg(not(feature = "wpe"))]
use enzui_webkit::session::ViewRequestId;
#[cfg(not(feature = "wpe"))]
use enzui_webkit::web::ViewId;
#[cfg(not(feature = "wpe"))]
use enzui_webkit::web::policy::{PermissionKind, RequestKind};
#[cfg(not(feature = "wpe"))]
use iced::advanced::widget::Operation;
#[cfg(not(feature = "wpe"))]
use iced::{Element, Size};
#[cfg(not(feature = "wpe"))]
use iced_test::runtime::user_interface::{Cache, UserInterface};
#[cfg(not(feature = "wpe"))]
use std::path::PathBuf;
#[cfg(not(feature = "wpe"))]
use std::sync::Arc;
#[cfg(not(feature = "wpe"))]
use std::time::{Duration, Instant};

#[cfg(not(feature = "wpe"))]
type Renderer = iced_test::renderer::Renderer;

#[cfg(not(feature = "wpe"))]
fn labels(app: &App) -> Vec<String> {
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
    collector
        .into_collected()
        .into_iter()
        .filter_map(|CollectedNode { semantics, .. }| semantics.label)
        .collect()
}

#[cfg(not(feature = "wpe"))]
fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    condition()
}

/// Toolkit focus plus the page field: real click under WPE (IME owner on
/// WebKit's report), synthetic report when feature-off - both production paths.
#[cfg(not(feature = "wpe"))]
fn seed_route_focus(app: &mut App) {
    let _ = app.update(Message::WebViewFocusGained);
    let _ = app.update(Message::WebViewFocusTextInput);
}

/// One unresolved policy request plus a live assertion per later absence check.
#[cfg(not(feature = "wpe"))]
fn seed_policy_and_assert_controls(app: &mut App) -> (ViewId, ViewRequestId) {
    let mut svc = app.webview.borrow_mut();
    let view = svc.live_view.expect("service has a live view");
    let pending_policy = svc
        .session
        .open(view, RequestKind::Permission(PermissionKind::Camera));
    let _ = svc
        .policy
        .open(RequestKind::Permission(PermissionKind::Camera));

    assert!(svc.router.accepts(view), "positive live-id control");
    assert!(svc.session.is_live(view), "positive policy control");
    assert_eq!(svc.session.outstanding_for(view), 1);
    assert_eq!(svc.policy.outstanding_count(), 1);
    assert!(!svc.page_delivery.is_empty(), "positive a11y control");
    assert!(svc.page_ime.is_open(), "positive IME-owner control");
    assert!(svc.focus.is_focused(), "positive input-focus control");
    assert!(svc.native.is_some(), "positive native-owner control");
    assert!(
        svc.native_scratch.is_some(),
        "positive scratch-owner control"
    );
    (view, pending_policy)
}

/// Every held authority, owner and buffer gone.
#[cfg(not(feature = "wpe"))]
fn assert_authority_revoked(app: &App, old_view: ViewId, pending_policy: ViewRequestId) {
    let mut svc = app.webview.borrow_mut();
    assert_eq!(svc.live_view, None);
    assert_eq!(svc.router.live_count(), 0);
    assert!(!svc.router.accepts(old_view));
    assert!(!svc.session.is_live(old_view));
    assert_eq!(svc.session.outstanding_for(old_view), 0);
    assert!(
        matches!(
            svc.session.resolve(pending_policy),
            enzui_webkit::session::SessionResolve::ViewGone { .. }
        ),
        "a close-invalidated policy request must authorize nothing"
    );
    assert_eq!(svc.policy.outstanding_count(), 0);
    assert!(svc.page_delivery.is_empty(), "dead a11y tree retained");
    assert!(!svc.page_ime.is_open(), "dead IME owner retained");
    assert!(!svc.focus.is_focused(), "input focus authority retained");
    assert!(svc.native.is_none(), "native page owner retained");
    assert!(svc.native_scratch.is_none(), "scratch owner retained");
    assert_eq!(svc.native_viewport, None);
    assert_eq!(svc.native_view_focused, None);
    assert_eq!(svc.native_error, None);
    assert_eq!(svc.native_open_error, None);
    assert_eq!(svc.native_worker_error, None);
    assert!(svc.lifecycle.is_shut_down());
    assert_eq!(svc.lifecycle.held_buffers(), 0);
    assert!(!svc.is_visible(), "a closed widget must not route input");
    assert!(svc.frame_plan.is_none());
    assert_eq!(svc.sink.retained_buffers(), 0);
    assert_eq!(svc.sink.retained_bytes(), 0);
    assert!(
        svc.sink.displayed().is_none(),
        "displayed RGBA survived close"
    );
}

/// Rendered route reports closed; explicit reopen mints exactly the prepared
/// generation - never revives `old_view`.
#[cfg(not(feature = "wpe"))]
fn assert_route_reports_closed_then_reopens(
    app: &mut App,
    old_view: ViewId,
    seed_synthetic_frame: bool,
) {
    let rendered = labels(app);
    assert!(rendered.iter().any(|label| label.contains("no live view")));
    assert!(rendered.iter().any(|label| label.contains("no frame plan")));
    assert!(
        rendered
            .iter()
            .any(|label| label.contains("sink_retained=0"))
    );

    let _ = app.update(Message::WebViewRecreate);
    let reopened = app.webview.borrow().live_view.expect("reopened view");
    assert_ne!(reopened, old_view);
    assert!(app.webview.borrow().router.accepts(reopened));
    assert!(!app.webview.borrow().router.accepts(old_view));
    assert!(!app.webview.borrow().lifecycle.is_shut_down());
    assert_eq!(
        app.webview.borrow().sink_generation.raw(),
        reopened.generation().0,
        "close prepares exactly the generation that explicit reopen mints"
    );
    if seed_synthetic_frame {
        let _ = app.update(Message::WebViewOfferFrame);
        assert_eq!(app.webview.borrow().sink.retained_buffers(), 1);
    } else {
        assert_eq!(
            app.webview.borrow().sink.retained_buffers(),
            0,
            "the reopened sink must be empty before the second real WPE frame"
        );
    }
}

// Default build: no WPE - the native owner is an ownership witness.

/// Test-binary-side runtime dir, never `/tmp`.
#[cfg(not(feature = "wpe"))]
fn secure_scratch() -> (crate::webview_scratch::SecureScratch, PathBuf) {
    let base = std::env::current_exe()
        .expect("current executable")
        .parent()
        .expect("test binary directory")
        .join(format!(
            "webview-close-lifecycle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
    std::fs::create_dir_all(&base).expect("create close-test root");
    let runtime =
        enzui_core::runtime_dir::resolve(None, enzui_core::runtime_dir::current_uid(), &base)
            .expect("resolve target-local runtime directory");
    let scratch =
        crate::webview_scratch::SecureScratch::open_under_root(&runtime, "webview-close-lifecycle")
            .expect("open secure close-test scratch");
    (scratch, base)
}

#[cfg(not(feature = "wpe"))]
#[test]
fn production_close_revokes_authority_and_frees_every_buffer() {
    use std::sync::atomic::Ordering;

    let mut app = App::new(enzui_theme::EnzTheme::dark());

    // Displayed + in-flight + queued RGBA: 3 retained proves every slot.
    let _ = app.update(Message::WebViewOfferFrame);
    let _ = app.update(Message::WebViewOfferFrame);
    let _ = app.update(Message::WebViewPresentFrame);
    let _ = app.update(Message::WebViewOfferFrame);
    seed_route_focus(&mut app);

    let (scratch, scratch_root) = secure_scratch();
    let scratch = Arc::new(scratch);
    let scratch_path = scratch.path().to_owned();
    let (native, native_joined, scratch_seen_by_native) =
        crate::webview_native::NativePage::teardown_probe(Arc::clone(&scratch));
    {
        let mut svc = app.webview.borrow_mut();
        svc.native = Some(native);
        svc.native_scratch = Some(scratch);
        svc.native_viewport = Some(
            enzui_webkit::ViewportSize::from_logical(640.0, 480.0).expect("valid seeded viewport"),
        );
        svc.native_view_focused = Some(true);
        svc.native_error = Some("seed error that close must clear".to_owned());
    }

    let (old_view, pending_policy) = seed_policy_and_assert_controls(&mut app);
    {
        let svc = app.webview.borrow();
        assert!(scratch_path.exists(), "positive scratch-path control");
        assert_eq!(svc.sink.retained_buffers(), 3);
        assert!(svc.sink.displayed().is_some(), "displayed RGBA is seeded");
        assert!(svc.sink.retained_bytes() > 0, "real pixel bytes are seeded");
        assert_eq!(svc.lifecycle.held_buffers(), 3);
    }

    // Only the production dispatcher closes.
    let _ = app.update(Message::WebViewClose);

    assert_authority_revoked(&app, old_view, pending_policy);
    assert!(
        native_joined.load(Ordering::Acquire),
        "taking the native owner must run its Drop/join path before update returns"
    );
    assert!(
        scratch_seen_by_native.load(Ordering::Acquire),
        "the native owner must finish while its scratch directory still exists"
    );
    assert!(
        !scratch_path.exists(),
        "scratch must be released after native teardown: {}",
        scratch_path.display()
    );

    // Idempotent: second dispatch stays behind the reopen tombstone.
    let generation_after_close = app.webview.borrow().sink_generation;
    let _ = app.update(Message::WebViewClose);
    assert_eq!(
        app.webview.borrow().sink_generation,
        generation_after_close,
        "repeated close advanced only the sink generation"
    );

    assert_route_reports_closed_then_reopens(&mut app, old_view, true);

    // Over-budget workers detach under the stop flag; their lease outlives the
    // service's.
    let (timeout_scratch, timeout_root) = secure_scratch();
    let timeout_scratch = Arc::new(timeout_scratch);
    let timeout_path = timeout_scratch.path().to_owned();
    let (timeout_native, release_timeout_worker, timeout_worker_finished, native_drop_timed_out) =
        crate::webview_native::NativePage::teardown_timeout_probe(Arc::clone(&timeout_scratch));
    {
        let mut svc = app.webview.borrow_mut();
        svc.native = Some(timeout_native);
        svc.native_scratch = Some(timeout_scratch);
    }
    let _ = app.update(Message::WebViewClose);
    assert!(
        native_drop_timed_out.load(Ordering::Acquire),
        "NativePage::drop did not report the controlled timeout"
    );
    assert!(
        !timeout_worker_finished.load(Ordering::Acquire),
        "timeout witness unexpectedly finished before close returned"
    );
    assert!(
        timeout_path.exists(),
        "detached worker lost its scratch directory before it exited"
    );
    release_timeout_worker
        .send(())
        .expect("release detached timeout worker");
    assert!(
        wait_until(Duration::from_secs(1), || timeout_worker_finished
            .load(Ordering::Acquire)),
        "detached timeout worker did not exit"
    );
    assert!(
        wait_until(Duration::from_secs(1), || !timeout_path.exists()),
        "scratch was not cleaned after the detached worker exited"
    );

    let _ = std::fs::remove_dir_all(scratch_root);
    let _ = std::fs::remove_dir_all(timeout_root);
}

// `--features wpe`: the real engine through the real dispatcher.
