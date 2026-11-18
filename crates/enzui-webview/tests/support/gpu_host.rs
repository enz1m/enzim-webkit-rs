//! Drive the probe's production update and view on WPE's process main thread.

#[path = "../../../webview-probe/src/app.rs"]
#[allow(
    dead_code,
    reason = "This diagnostic example reuses production modules but exercises only part of their API."
)]
mod app;
#[path = "../../../webview-probe/src/diagnostic_log.rs"]
mod diagnostic_log;
#[path = "../../../webview-probe/src/message.rs"]
mod message;
#[path = "../../../webview-probe/src/native_interest.rs"]
mod native_interest;
#[path = "../../../webview-probe/src/update.rs"]
mod update;
#[path = "../../../webview-probe/src/webview.rs"]
mod webview;
#[path = "../../../webview-probe/src/webview_native.rs"]
#[allow(
    dead_code,
    reason = "This diagnostic example reuses production modules but exercises only part of their API."
)]
mod webview_native;
#[path = "../../../webview-probe/src/routes/webview_route.rs"]
mod webview_route;
#[path = "../../../webview-probe/src/webview_scratch.rs"]
mod webview_scratch;

use app::App;
use iced::advanced::renderer::Headless as _;
use iced::{Color, Size};
use iced_test::runtime::user_interface::{Cache, UserInterface};
use message::{Message, drain_a11y_actions, drain_a11y_wake};
use std::time::{Duration, Instant};

struct Screen {
    renderer: iced::Renderer,
    cache: Cache,
    messages: Vec<Message>,
}
impl Screen {
    fn new() -> Self {
        Self::backend(
            if std::env::args().any(|argument| argument == "--software") {
                "tiny-skia"
            } else {
                "wgpu"
            },
        )
    }
    fn backend(backend: &str) -> Self {
        Self {
            renderer: iced_test::futures::futures::executor::block_on(
                <iced::Renderer as iced::advanced::renderer::Headless>::new(
                    iced::advanced::renderer::Settings::default(),
                    Some(backend),
                ),
            )
            .expect("Vulkan renderer"),
            cache: Cache::default(),
            messages: Vec::new(),
        }
    }
    fn draw(&mut self, app: &mut App) -> Vec<u8> {
        for message in std::mem::take(&mut self.messages) {
            let _ = app.update(message);
        }
        let size = Size::new(1400.0, 1800.0);
        let mut ui = UserInterface::build(
            app.view(),
            size,
            std::mem::take(&mut self.cache),
            &mut self.renderer,
        );
        let mut messages = iced::advanced::shell::Bus::new();
        ui.update(
            &iced::window::Headless,
            &iced::advanced::graphics::core::shell::Waker::noop(),
            &[iced::Event::Window(iced::window::Event::RedrawRequested(
                iced::time::Instant::now(),
            ))],
            iced::mouse::Cursor::Unavailable,
            &mut self.renderer,
            &mut messages,
        );
        ui.draw(
            &mut self.renderer,
            &app.theme(),
            &iced::advanced::renderer::Style {
                text_color: Color::WHITE,
            },
            iced::mouse::Cursor::Unavailable,
        );
        self.cache = ui.into_cache();
        self.messages.extend(messages);
        self.renderer
            .screenshot(Size::new(1400, 1800), 1.0, Color::BLACK)
    }
}

fn wait(
    app: &mut App,
    screen: &mut Screen,
    phase: &str,
    mut ready: impl FnMut(&App, &[u8]) -> bool,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let _ = app.update(Message::WebViewNativeReady);
        let _ = app.subscription();
        let pixels = screen.draw(app);
        assert!(
            app.webview.borrow().native_error.is_none(),
            "{phase}: {:?}",
            app.webview.borrow().native_error
        );
        if ready(app, &pixels) {
            return pixels;
        }
        if Instant::now() >= deadline {
            std::fs::write("work/rendering/http2/gpu-host-failure.rgba", &pixels).unwrap();
            let service = app.webview.borrow();
            panic!(
                "{phase}: frame={:?} dom={:?} logs={:?}",
                service.gpu_frame.as_ref().map(|f| f.status()),
                service.dom_report,
                service.log
            );
        }
        std::thread::sleep(Duration::from_millis(8));
    }
}

fn page_visible(pixels: &[u8]) -> bool {
    pixels
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|pixel| pixel[..3] == [18, 22, 34])
        .count()
        > 10_000
}

fn main() {
    #[cfg(feature = "diagnostics")]
    if std::env::args().any(|arg| arg == "--metadata-check") {
        let scratch = webview_scratch::SecureScratch::open_for_native_webview()
            .expect("private metadata scratch");
        webview_native::run_metadata_gate(scratch.path().to_path_buf()).expect("metadata gate");
        return;
    }

    assert!(
        enzui_webkit::ffi::native_requires_process_main_thread(),
        "select the pinned nightly runtime"
    );
    let (mut app, _) = App::boot();
    if std::env::args().any(|argument| argument == "--cancel-startup") {
        let _ = app.update(Message::WebViewOpenNative);
        assert!(app.pending_native_open);
        assert!(app.webview.borrow().native.is_none());
        let _ = app.update(Message::WebViewClose);
        let mut screen = Screen::new();
        wait(
            &mut app,
            &mut screen,
            "cancelled startup",
            |app, _pixels| app.renderer_ready,
        );
        assert!(!app.pending_native_open);
        assert!(app.webview.borrow().native.is_none());
        assert!(app.webview.borrow().native_error.is_none());
        println!("Cancelled startup stays closed after actual renderer readiness");
        return;
    }
    #[cfg(feature = "diagnostics")]
    if std::env::args().any(|argument| argument == "--refused-lease") {
        let _ = app.update(Message::WebViewOpenNative);
        let mut initial = Screen::backend("wgpu");
        wait(
            &mut app,
            &mut initial,
            "initial renderer capabilities",
            |app, _pixels| page_visible(_pixels) && app.webview.borrow().gpu_frame.is_some(),
        );
        assert!(enzui_webview::gpu::renderer_support().flatten().is_some());
        let mut software = Screen::backend("tiny-skia");
        software.draw(&mut app);
        let alive = {
            let service = app.webview.borrow();
            let frame = service.gpu_frame.as_ref().expect("native GPU frame");
            assert!(matches!(
                frame.status(),
                enzui_webview::gpu::GpuStatus::Refused(_)
            ));
            frame.lifetime_probe()
        };
        drop(software);
        drop(initial);
        assert!(
            alive(),
            "positive control: refused frame is still owned by the host"
        );
        let _ = app.update(Message::WebViewNativeReady);
        assert!(
            !alive(),
            "the host retained a rejected producer frame during format negotiation"
        );
        let mut screen = Screen::backend("tiny-skia");
        let pixels = wait(&mut app, &mut screen, "CPU after refusal", |app, pixels| {
            let service = app.webview.borrow();
            page_visible(pixels)
                && service.gpu_frame.is_none()
                && service.displayed_frame().is_some()
        });
        assert!(
            pixels
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|pixel| pixel[..3] == [18, 22, 34])
                .count()
                > 10_000
        );
        close(&mut app, screen);
        println!(
            "Rejected compositor owner released; software renderer receives actual CPU fallback pixels"
        );
        return;
    }
    let mut screen = Screen::new();
    let _ = app.update(Message::WebViewOpenNative);
    assert!(app.pending_native_open);
    assert!(app.webview.borrow().native.is_none());
    assert!(enzui_webview::gpu::renderer_support().is_none());
    enzui_webkit::ffi::runtime::reset_native_runtime_counters();
    if std::env::args().any(|argument| argument == "--software") {
        let pixels = wait(
            &mut app,
            &mut screen,
            "software fallback",
            |app, _pixels| {
                let service = app.webview.borrow();
                service.gpu_frame.is_none() && service.displayed_frame().is_some()
            },
        );
        assert!(
            pixels
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|pixel| pixel[..3] == [18, 22, 34])
                .count()
                > 10_000
        );
        let counters = enzui_webkit::ffi::runtime::native_runtime_counters();
        assert!(
            counters.snapshots_completed > 0 && counters.frame_copy_bytes > 0,
            "software host takes the actual CPU path"
        );
        close(&mut app, screen);
        println!(
            "Default software application route: GPU refusal produces an actual CPU page frame"
        );
        return;
    }
    let pixels = wait(
        &mut app,
        &mut screen,
        "initial default route",
        |app, _pixels| {
            page_visible(_pixels)
                && app
                    .webview
                    .borrow()
                    .gpu_frame
                    .as_ref()
                    .is_some_and(|frame| frame.status() == enzui_webview::gpu::GpuStatus::Imported)
        },
    );
    assert!(
        pixels
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|pixel| pixel[..3] == [18, 22, 34])
            .count()
            > 10_000,
        "the actual route shows the page background"
    );
    assert!(
        enzui_webkit::ffi::presentation::gpu_transport_counters().metadata_created > 0,
        "default host adopts shared native allocation metadata"
    );
    let output = std::env::args().nth(1).expect("output RGBA path");
    std::fs::write(output, &pixels).expect("capture actual application route");
    let old = app.webview.borrow().live_view.unwrap();
    for index in 0..16_u16 {
        let ticks = app.webview.borrow().native_ticks;
        app.webview
            .borrow_mut()
            .native_hover(60.0 + f32::from(index), 80.0);
        wait(
            &mut app,
            &mut screen,
            "unchanged native IME",
            |app, _pixels| app.webview.borrow().native_ticks > ticks,
        );
    }
    assert!(
        !app.webview
            .borrow()
            .log
            .iter()
            .any(|line| line == "native IME report -> Unchanged"),
        "unchanged native reports allocate no diagnostic history"
    );
    assert!(
        app.webview.borrow().sandbox_checks >= 2,
        "initial native publication refreshes the sandbox diagnostic"
    );
    assert!(
        app.webview
            .borrow()
            .sandbox_status
            .contains("isolated via bwrap"),
        "published sandbox diagnostic describes the live renderer"
    );
    let size = enzui_webkit::ViewportSize::from_logical(640.0, 480.0).unwrap();
    let _ = app.update(Message::WebViewViewportResize(old, size));
    wait(
        &mut app,
        &mut screen,
        "native GPU resize",
        |app, _pixels| {
            app.webview
                .borrow()
                .gpu_frame
                .as_ref()
                .is_some_and(|frame| {
                    frame.size() == (640, 480)
                        && frame.status() == enzui_webview::gpu::GpuStatus::Imported
                })
        },
    );
    let _ = app.update(Message::WebViewNativeClick(60.0, 140.0));
    wait(&mut app, &mut screen, "native input", |app, _pixels| {
        app.webview
            .borrow()
            .dom_report
            .as_ref()
            .is_some_and(|report| report.contains("|t|"))
    });
    assert!(
        app.webview
            .borrow()
            .log
            .iter()
            .any(|line| line == "native IME report -> Opened"),
        "actual native focus transitions remain observable"
    );
    let _ = app.update(Message::WebViewHide);
    assert!(app.webview.borrow().gpu_frame.is_none());
    let hidden = screen.draw(&mut app);
    assert_eq!(
        hidden
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|pixel| pixel[..3] == [18, 22, 34])
            .count(),
        0,
        "hidden route shows no page pixels"
    );
    let _ = app.update(Message::WebViewShow);
    wait(&mut app, &mut screen, "show", |app, _pixels| {
        app.webview
            .borrow()
            .gpu_frame
            .as_ref()
            .is_some_and(|frame| frame.status() == enzui_webview::gpu::GpuStatus::Imported)
    });
    let _ = app.update(Message::WebViewRecreate);
    wait(
        &mut app,
        &mut screen,
        "recreated generation",
        |app, _pixels| {
            let service = app.webview.borrow();
            service.live_view != Some(old)
                && service.gpu_frame.as_ref().is_some_and(|frame| {
                    frame.view() == service.live_view.unwrap()
                        && frame.status() == enzui_webview::gpu::GpuStatus::Imported
                })
        },
    );
    let _ = app.update(Message::WebViewHide);
    let _ = app.update(Message::WebViewRecreate);
    let hidden_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < hidden_until {
        let _ = app.update(Message::WebViewNativeReady);
        screen.draw(&mut app);
        assert!(
            app.webview.borrow().gpu_frame.is_none(),
            "hidden recovery publishes no GPU pixels"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = app.update(Message::WebViewShow);
    wait(
        &mut app,
        &mut screen,
        "show after hidden recovery",
        |app, _pixels| {
            app.webview
                .borrow()
                .gpu_frame
                .as_ref()
                .is_some_and(|frame| frame.status() == enzui_webview::gpu::GpuStatus::Imported)
        },
    );
    let counters = enzui_webkit::ffi::runtime::native_runtime_counters();
    assert_eq!(counters.snapshots_completed, 0, "GPU host never snapshots");
    assert_eq!(
        counters.frame_copy_bytes, 0,
        "GPU host never copies page pixels"
    );
    close(&mut app, screen);
    println!(
        "Default application GPU route: imported pixels, native input, hide/show, recreate, close, zero snapshot copies"
    );
}

fn close(app: &mut App, screen: Screen) {
    let _ = app.update(Message::WebViewClose);
    drop(screen);
    let deadline = Instant::now() + Duration::from_secs(5);
    while enzui_webkit::ffi::presentation::pending_gpu_frame_completions() != 0 {
        let _ = app.update(Message::WebViewNativeReady);
        assert!(
            Instant::now() < deadline,
            "closed page releases final GPU holds"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
