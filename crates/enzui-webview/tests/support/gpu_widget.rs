//! Verify WPE compositor frames through the default web widget and shared renderer.

use enzui_webkit::ffi::presentation::SharedGpuFrame;
use enzui_webkit::ffi::runtime::{
    HeadlessDisplay, WebSession, native_runtime_counters, reset_native_runtime_counters,
};
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::web::{ViewId, ViewRouter};
use enzui_webview::{enz_web_view, gpu::GpuFrame};
use iced::advanced::renderer::Headless as _;
use iced::{Color, Element, Size};
use iced_test::runtime::user_interface::{Cache, UserInterface};
use std::time::{Duration, Instant};

const HTML: &str = "<style>html,body{margin:0;width:100%;height:100%;background:#ff0000}div{position:absolute;width:50%;height:50%}#b{left:50%;background:#00ff00}#c{top:50%;background:#0000ff}#d{left:50%;top:50%;background:#ffffff}</style><div id=b></div><div id=c></div><div id=d></div>";

struct Screen {
    renderer: iced::Renderer,
    cache: Cache,
}
impl Screen {
    fn new() -> Self {
        Self::backend("wgpu")
    }
    fn backend(backend: &str) -> Self {
        let renderer = iced_test::futures::futures::executor::block_on(
            <iced::Renderer as iced::advanced::renderer::Headless>::new(
                iced::advanced::renderer::Settings::default(),
                Some(backend),
            ),
        )
        .expect("Vulkan renderer");
        Self {
            renderer,
            cache: Cache::default(),
        }
    }
    fn shot(&mut self, view: Element<'_, ()>) -> Vec<u8> {
        let mut ui = UserInterface::build(
            view,
            Size::new(320.0, 240.0),
            std::mem::take(&mut self.cache),
            &mut self.renderer,
        );
        ui.draw(
            &mut self.renderer,
            &iced::Theme::Dark,
            &iced::advanced::renderer::Style {
                text_color: Color::WHITE,
            },
            iced::mouse::Cursor::Unavailable,
        );
        self.cache = ui.into_cache();
        self.renderer
            .screenshot(Size::new(320, 240), 1.0, Color::BLACK)
    }
}

fn take(session: &WebSession, router: &ViewRouter, view: ViewId) -> SharedGpuFrame {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "compositor produced a frame");
        session.pump(5);
        if let Some(frame) = session
            .take_shared_gpu_frame(router, view)
            .expect("native frame")
        {
            println!(
                "buffer={} format={:#x} modifier={:#x} planes={}",
                frame.buffer_id(),
                frame.buffer().format(),
                frame.buffer().modifier(),
                frame.buffer().planes().len()
            );
            return frame;
        }
    }
}

fn evaluate(session: &WebSession, script: &str) {
    let id = session
        .evaluate_script(script, &ScriptWorld::Isolated("widget-gpu-probe".into()))
        .expect("script");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "script completed");
        session.pump(5);
        if session.take_page_events().iter().any(|event| matches!(event, PageEvent::ScriptResult {id: found,result: Ok(_)} if *found==id)) { return; }
    }
}

fn plane_descriptor_counts(native: &SharedGpuFrame) -> Vec<(u64, u64, usize)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    native
        .buffer()
        .planes()
        .iter()
        .map(|plane| {
            let metadata =
                std::fs::metadata(format!("/proc/self/fd/{}", plane.fd.as_raw_fd())).unwrap();
            let (device, inode) = (metadata.dev(), metadata.ino());
            (device, inode, descriptor_count(device, inode))
        })
        .collect()
}

fn descriptor_count(device: u64, inode: u64) -> usize {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::metadata(entry.path()).ok())
        .filter(|metadata| metadata.dev() == device && metadata.ino() == inode)
        .count()
}

fn adapt(native: SharedGpuFrame) -> GpuFrame {
    let before = plane_descriptor_counts(&native);
    let frame = std::thread::spawn(move || {
        let allocation = native.buffer_id();
        GpuFrame::from_shared_native(native, allocation)
    })
    .join()
    .expect("descriptor handoff to consumer thread");
    for (device, inode, count) in before {
        assert_eq!(
            descriptor_count(device, inode),
            count,
            "shared adapter does not duplicate plane descriptors"
        );
    }
    frame
}

fn quadrants(pixels: &[u8], red: u8) {
    for (x, y, expected) in [
        (80, 60, [red, 0, 0, 255]),
        (240, 60, [0, 255, 0, 255]),
        (80, 180, [0, 0, 255, 255]),
        (240, 180, [255, 255, 255, 255]),
    ] {
        let at = (y * 320 + x) * 4;
        assert_eq!(&pixels[at..at + 4], &expected, "widget pixel at {x},{y}");
    }
}

fn live_source_gate(
    session: &WebSession,
    router: &mut ViewRouter,
    view: ViewId,
    screen: &mut Screen,
    frame: GpuFrame,
) {
    let source = enzui_webview::gpu::GpuFrameSource::new(view);
    assert!(source.publish(&frame, router));
    quadrants(
        &screen.shot(
            enz_web_view(view, None, true)
                .gpu_source(&source, router)
                .into(),
        ),
        255,
    );
    let mut latest = frame;
    let mut previous = latest.content_info();
    let mut partial = 0;
    for index in 0..12 {
        let red = if index % 2 == 0 { 204 } else { 255 };
        evaluate(
            session,
            &format!("document.body.style.background='rgb({red},0,0)';true"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < deadline,
                "live source updates cached rendering without a new widget draw"
            );
            let native = take(session, router, view);
            let info = native.content_info();
            assert_eq!(info.extent(), native.buffer().size());
            assert!(
                info.serial() > previous.serial(),
                "content serial advances across allocation reuse"
            );
            if matches!(
                info.damage_since(Some(previous)),
                enzui_webkit::frame_damage::FrameDamage::Region(_)
            ) {
                partial += 1;
            }
            previous = info;
            latest = adapt(native);
            assert!(source.publish(&latest, router));
            let pixels = screen
                .renderer
                .screenshot(Size::new(320, 240), 1.0, Color::BLACK);
            if pixels[(60 * 320 + 80) * 4] == red {
                quadrants(&pixels, red);
                break;
            }
        }
    }
    assert!(
        partial > 0,
        "native render damage survives the engine and adapter exports"
    );
    source.clear();
    let cleared = screen
        .renderer
        .screenshot(Size::new(320, 240), 1.0, Color::BLACK);
    assert!(
        cleared
            .as_chunks::<4>()
            .0
            .iter()
            .all(|p| p[..3] == [0, 0, 0]),
        "cleared live source removes old GPU pixels from cached scene"
    );
    let foreign = router.create(2);
    let foreign_source = enzui_webview::gpu::GpuFrameSource::new(foreign);
    assert!(!foreign_source.publish(&latest, router));
    assert!(foreign_source.size().is_none());
    let next = router.recreate(view.slot());
    assert!(
        !source.publish(&latest, router),
        "revoked source rejects old frame publication"
    );
    assert!(source.size().is_none());
    println!(
        "Live source completed: 12 cached-renderer updates, correct pixels, cleared pixels, foreign and revoked publication refused; partial regions={partial}; next={next:?}"
    );
}

fn main() {
    let display = HeadlessDisplay::new().expect("native display on process main thread");
    let mut session = WebSession::new(&display).expect("attested session");
    let mut router = ViewRouter::new();
    let view = router.create(1);
    session.bind_view(&router, view).expect("bind");
    session
        .resize_viewport(
            &router,
            view,
            enzui_webkit::ViewportSize::from_logical(320.0, 240.0).unwrap(),
        )
        .unwrap();
    session.enable_gpu_presentation();
    session
        .load_html(HTML, "about:blank", 5000)
        .expect("document loaded");
    reset_native_runtime_counters();
    let native = take(&session, &router, view);
    let mut frame = adapt(native);
    let mut screen = Screen::new();
    let mut pixels = screen.shot(
        enz_web_view(view, None, true)
            .gpu_frame(&frame, &router)
            .into(),
    );
    if frame.status() != enzui_webview::gpu::GpuStatus::Imported {
        let support = enzui_webview::gpu::renderer_support()
            .flatten()
            .expect("renderer DMA-BUF layouts");
        assert!(!support.formats.is_empty());
        assert!(session.set_gpu_buffer_formats(&router, view, &support.formats));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "negotiated compositor format");
            println!("Discarding unencoded import outcome: {:?}", frame.status());
            frame.discard();
            drop(frame);
            let native = take(&session, &router, view);
            frame = adapt(native);
            pixels = screen.shot(
                enz_web_view(view, None, true)
                    .gpu_frame(&frame, &router)
                    .into(),
            );
            if frame.status() == enzui_webview::gpu::GpuStatus::Imported {
                break;
            }
        }
    }
    assert_eq!(
        frame.status(),
        enzui_webview::gpu::GpuStatus::Imported,
        "actual Vulkan import"
    );
    quadrants(&pixels, 255);
    if std::env::args().any(|arg| arg == "--source-check") {
        live_source_gate(&session, &mut router, view, &mut screen, frame);
        drop(screen);
        let deadline = Instant::now() + Duration::from_secs(5);
        while enzui_webkit::ffi::presentation::pending_gpu_frame_completions() != 0 {
            assert!(Instant::now() < deadline, "cleared source leases retire");
            session.pump(5);
        }
        return;
    }
    let baseline = enzui_external_image::imports_made();
    quadrants(
        &screen.shot(
            enz_web_view(view, None, true)
                .gpu_frame(&frame, &router)
                .into(),
        ),
        255,
    );
    assert_eq!(
        enzui_external_image::imports_made(),
        baseline,
        "replay reuses the imported allocation"
    );
    drop(frame);
    for index in 0..24 {
        let red = if index % 2 == 0 { 204 } else { 255 };
        evaluate(
            &session,
            &format!("document.body.style.background='rgb({red},0,0)';true"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < deadline,
                "requested colour reached the widget"
            );
            let native = take(&session, &router, view);
            let frame = adapt(native);
            let pixels = screen.shot(
                enz_web_view(view, None, true)
                    .gpu_frame(&frame, &router)
                    .into(),
            );
            assert_eq!(frame.status(), enzui_webview::gpu::GpuStatus::Imported);
            if pixels[(60 * 320 + 80) * 4] == red {
                quadrants(&pixels, red);
                break;
            }
        }
    }
    let counters = native_runtime_counters();
    assert_eq!(counters.snapshots_completed, 0);
    assert_eq!(counters.frame_copy_bytes, 0);
    evaluate(
        &session,
        "document.body.style.background='rgb(204,0,0)';true",
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let frame = loop {
        assert!(Instant::now() < deadline);
        let native = take(&session, &router, view);
        let frame = adapt(native);
        let pixels = screen.shot(
            enz_web_view(view, None, true)
                .gpu_frame(&frame, &router)
                .into(),
        );
        if pixels[(60 * 320 + 80) * 4] == 204 {
            quadrants(&pixels, 204);
            break frame;
        }
    };
    let mut software = Screen::backend("tiny-skia");
    let fallback = enzui_core::media::Rgba8Frame::new(
        enzui_core::media::Generation::FIRST,
        enzui_core::frame_plan::FrameSeq(1),
        320,
        240,
        [200, 0, 200, 255].repeat(320 * 240),
    )
    .unwrap();
    let pixels = software.shot(
        enz_web_view(view, Some(&fallback), true)
            .gpu_frame(&frame, &router)
            .into(),
    );
    assert_eq!(
        frame.status(),
        enzui_webview::gpu::GpuStatus::Refused(enzui_webview::gpu::GpuRefusal::NoImport)
    );
    assert_eq!(
        &pixels[(60 * 320 + 80) * 4..(60 * 320 + 80) * 4 + 4],
        &[200, 0, 200, 255]
    );
    drop(software);
    let foreign = router.create(2);
    let pixels = screen.shot(
        enz_web_view(foreign, None, true)
            .gpu_frame(&frame, &router)
            .into(),
    );
    assert_ne!(
        &pixels[(60 * 320 + 80) * 4..(60 * 320 + 80) * 4 + 4],
        &[204, 0, 0, 255],
        "foreign GPU pixels are refused"
    );
    router.recreate(view.slot());
    let pixels = screen.shot(
        enz_web_view(view, None, true)
            .gpu_frame(&frame, &router)
            .into(),
    );
    assert_ne!(
        &pixels[(60 * 320 + 80) * 4..(60 * 320 + 80) * 4 + 4],
        &[204, 0, 0, 255],
        "revoked GPU generation is refused"
    );
    drop(screen);
    std::thread::spawn(move || drop(frame))
        .join()
        .expect("final release on consumer thread");
    let deadline = Instant::now() + Duration::from_secs(5);
    while enzui_webkit::ffi::presentation::pending_gpu_frame_completions() != 0 {
        assert!(
            Instant::now() < deadline,
            "GPU completion releases native holds"
        );
        session.pump(5);
    }
    println!(
        "Default GPU widget probe completed: actual pixels, cached replay, 24 updates, zero native snapshot copies"
    );
}
