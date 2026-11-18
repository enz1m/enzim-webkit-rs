//! Main-thread compositor-buffer probe for installed and development WPE runtimes.

#[path = "support/egl_probe.rs"]
#[allow(
    unsafe_code,
    reason = "probe imports an actual EGLImage and reads one diagnostic GPU pixel"
)]
mod egl_probe;

use enzui_webkit::ffi::presentation::DmaBufFrame;
use enzui_webkit::ffi::runtime::{
    HeadlessDisplay, WebSession, native_runtime_counters, reset_native_runtime_counters,
};
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::viewport::ViewportSize;
use enzui_webkit::web::{ViewId, ViewRouter};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

fn evaluate(session: &WebSession, source: &str) {
    let id = session
        .evaluate_script(source, &ScriptWorld::Page)
        .expect("evaluate page");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "JavaScript completion");
        session.pump(2);
        for event in session.take_page_events() {
            if let PageEvent::ScriptResult { id: found, result } = event
                && id == found
            {
                result.expect("page script result");
                return;
            }
        }
    }
}

fn next(session: &WebSession, router: &ViewRouter, view: ViewId) -> DmaBufFrame {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(frame) = session
            .take_gpu_frame(router, view)
            .expect("GPU frame export")
        {
            return frame;
        }
        assert!(Instant::now() < deadline, "compositor frame delivered");
        session.pump(2);
    }
}

fn matching(
    session: &WebSession,
    router: &ViewRouter,
    view: ViewId,
    colour: [u8; 4],
) -> DmaBufFrame {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < deadline,
            "compositor painted requested colour"
        );
        let frame = next(session, router, view);
        assert_eq!(frame.view(), view);
        if frame.size() != (320, 240) {
            continue;
        }
        assert!((1..=4).contains(&frame.planes().len()));
        assert!(frame.planes().iter().all(|plane| plane.stride > 0));
        if egl_probe::pixel(&frame) == colour {
            return frame;
        }
    }
}

fn allocation_descriptors(kind: &std::path::Path) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("native descriptor census")
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|target| target == kind)
        .count()
}

fn completion_lifecycle(
    session: WebSession,
    display: &HeadlessDisplay,
    router: &mut ViewRouter,
    view: ViewId,
) {
    use enzui_webkit::ffi::presentation::pending_gpu_frame_completions;
    let mut held = Vec::new();
    for index in 0..3 {
        evaluate(
            &session,
            &format!(
                "document.body.style.background='rgb({},40,80)'",
                80 + index * 30
            ),
        );
        let frame = next(&session, router, view).into_thread_safe().unwrap();
        let ack = session.acknowledged_frames();
        let (planes, completion) = frame.into_parts();
        for _ in 0..100 {
            completion.clone().presented();
        }
        held.push((planes, completion));
        if index < 2 {
            let deadline = Instant::now() + Duration::from_secs(3);
            while session.acknowledged_frames() <= ack {
                assert!(Instant::now() < deadline, "held completion acknowledged");
                session.pump(2);
            }
        }
    }
    let ack = session.acknowledged_frames();
    evaluate(&session, "document.body.style.background='rgb(90,50,110)'");
    session.pump(40);
    assert_eq!(
        session.acknowledged_frames(),
        ack,
        "shared completion transport preserves three-frame backpressure"
    );
    assert!(!session.gpu_frame_pending());
    drop(session);
    assert_eq!(pending_gpu_frame_completions(), 3);
    for remaining in [2, 1] {
        drop(held.pop());
        let deadline = Instant::now() + Duration::from_secs(3);
        while pending_gpu_frame_completions() != remaining {
            assert!(Instant::now() < deadline, "reverse release after close");
            enzui_webkit::ffi::dispatch_pending_native_events().unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let replacement = router.recreate(view.slot());
    let mut next_session = WebSession::new(display).unwrap();
    next_session.bind_view(router, replacement).unwrap();
    next_session.enable_gpu_presentation();
    next_session
        .load_html("<style>body{background:green}</style>", "about:blank", 5000)
        .unwrap();
    let new_frame = next(&next_session, router, replacement)
        .into_thread_safe()
        .unwrap();
    assert_eq!(new_frame.view(), replacement);
    drop(new_frame);
    let deadline = Instant::now() + Duration::from_secs(3);
    while pending_gpu_frame_completions() != 1 {
        assert!(
            Instant::now() < deadline,
            "discarded new-generation frame releases independently"
        );
        next_session.pump(2);
    }
    drop(next_session);
    let last = held.pop().unwrap();
    std::thread::spawn(move || drop(last)).join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while pending_gpu_frame_completions() != 0 {
        assert!(
            Instant::now() < deadline,
            "old-generation final release on another thread"
        );
        enzui_webkit::ffi::dispatch_pending_native_events().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    println!(
        "Completion lifecycle completed: cloned tokens, three held frames, reverse release, closed session, new generation, discarded frame, late cross-thread release"
    );
}

/// A consumer on the native owner thread is acknowledged and released where
/// it calls, with no dispatch in between; one on another thread still waits
/// for the owner's dispatch.
fn owner_completion(session: WebSession, router: &ViewRouter, view: ViewId) {
    use enzui_webkit::ffi::presentation::pending_gpu_frame_completions;
    for index in 0..3 {
        evaluate(
            &session,
            &format!(
                "document.body.style.background='rgb(60,{},120)'",
                70 + index * 40
            ),
        );
        let frame = next(&session, router, view).into_thread_safe().unwrap();
        let acknowledged = session.acknowledged_frames();
        let (planes, completion) = frame.into_parts();
        assert_eq!(pending_gpu_frame_completions(), 1);
        completion.presented();
        assert_eq!(
            session.acknowledged_frames(),
            acknowledged + 1,
            "presentation on the owner thread is acknowledged without a dispatch"
        );
        completion.clone().presented();
        assert_eq!(
            session.acknowledged_frames(),
            acknowledged + 1,
            "a frame is acknowledged once"
        );
        assert_eq!(
            pending_gpu_frame_completions(),
            1,
            "presentation keeps the consumer's lease"
        );
        drop((planes, completion));
        assert_eq!(
            pending_gpu_frame_completions(),
            0,
            "the last clone dropped on the owner thread releases without a dispatch"
        );
    }
    evaluate(&session, "document.body.style.background='rgb(200,60,40)'");
    let frame = next(&session, router, view).into_thread_safe().unwrap();
    let acknowledged = session.acknowledged_frames();
    let (planes, completion) = frame.into_parts();
    std::thread::spawn(move || {
        completion.presented();
        drop((planes, completion));
    })
    .join()
    .unwrap();
    assert_eq!(
        (
            session.acknowledged_frames(),
            pending_gpu_frame_completions()
        ),
        (acknowledged, 1),
        "another thread's presentation and release wait for the owner's dispatch"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while pending_gpu_frame_completions() != 0 {
        assert!(
            Instant::now() < deadline,
            "cross-thread release reaches the owner"
        );
        session.pump(2);
    }
    assert!(session.acknowledged_frames() > acknowledged);
    println!(
        "Owner completion completed: acknowledged and released in place on the owner thread, by dispatch from another"
    );
}

fn next_shared_export(
    session: &WebSession,
    router: &ViewRouter,
    view: ViewId,
) -> enzui_webkit::ffi::presentation::SharedGpuFrame {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(frame) = session.take_shared_gpu_frame(router, view).unwrap() {
            return frame;
        }
        assert!(Instant::now() < deadline, "buffer export arrives");
        session.pump(2);
    }
}

fn shared_buffer_lifecycle(mut session: WebSession, router: &ViewRouter, view: ViewId) {
    use enzui_webkit::ffi::presentation::{gpu_transport_counters, pending_gpu_frame_completions};
    drop(matching(&session, router, view, [20, 100, 240, 255]));
    let before = gpu_transport_counters();
    let mut identities = std::collections::HashMap::new();
    for index in 0..24 {
        evaluate(
            &session,
            &format!(
                "document.body.style.background='rgb({},50,100)'",
                20 + index * 5
            ),
        );
        let frame = next_shared_export(&session, router, view);
        assert_eq!(frame.buffer().size(), (320, 240));
        if let Some(kept) = identities.get(&frame.buffer_id()) {
            assert!(
                std::sync::Arc::ptr_eq(kept, frame.buffer()),
                "native allocation reuses the exact metadata object"
            );
        } else {
            identities.insert(frame.buffer_id(), std::sync::Arc::clone(frame.buffer()));
        }
        drop(frame);
        let deadline = Instant::now() + Duration::from_secs(3);
        while pending_gpu_frame_completions() != 0 {
            assert!(Instant::now() < deadline, "shared frame discard completes");
            session.pump(2);
        }
    }
    assert!(identities.len() <= 4);
    session
        .resize_viewport(
            router,
            view,
            ViewportSize::from_logical(640.0, 480.0).unwrap(),
        )
        .unwrap();
    evaluate(&session, "document.body.style.background='purple'");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut attempts = 0;
    let resized = loop {
        evaluate(
            &session,
            &format!(
                "document.body.style.background='rgb({},70,130)'",
                100 + attempts % 100
            ),
        );
        attempts += 1;
        let frame = next_shared_export(&session, router, view);
        if frame.buffer().size() == (640, 480) {
            break frame;
        }
        drop(frame);
        session.pump(2);
        assert!(
            Instant::now() < deadline,
            "resize receives new allocation metadata"
        );
    };
    assert!(
        !identities.contains_key(&resized.buffer_id()),
        "resize uses a new allocation identity"
    );
    let metadata = std::sync::Arc::clone(resized.buffer());
    let fd = metadata.planes()[0].fd.as_raw_fd();
    drop(identities);
    drop(resized);
    drop(session);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        enzui_webkit::ffi::dispatch_pending_native_events().unwrap();
        let after = gpu_transport_counters();
        if pending_gpu_frame_completions() == 0
            && after.metadata_created - before.metadata_created
                == after.metadata_dropped - before.metadata_dropped + 1
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native allocation retirement releases unheld metadata: {after:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        std::fs::read_link(format!("/proc/self/fd/{fd}")).is_ok(),
        "metadata alone retains its descriptor after native retirement"
    );
    std::thread::spawn(move || drop(metadata)).join().unwrap();
    let after = gpu_transport_counters();
    assert_eq!(
        after.metadata_created - before.metadata_created,
        after.metadata_dropped - before.metadata_dropped,
        "last metadata owner releases the retired allocation"
    );
    assert!(
        std::fs::read_link(format!("/proc/self/fd/{fd}")).is_err(),
        "metadata's descriptor closes after its final owner"
    );
    println!(
        "Shared buffer lifecycle completed: allocation identity, reuse, resize, native retirement, independent metadata ownership, descriptor closure"
    );
}

fn main() {
    if std::env::args().any(|argument| argument == "--expect-main-thread") {
        assert!(
            enzui_webkit::ffi::native_requires_process_main_thread(),
            "nightly reports its main-thread requirement"
        );
        std::thread::spawn(|| {
            assert!(
                matches!(
                    enzui_webkit::ffi::profile::NetworkSession::new_ephemeral(),
                    Err(enzui_webkit::ffi::profile::ProfileError::WrongThread(_))
                ),
                "nightly refuses the first native constructor on a worker thread"
            );
        })
        .join()
        .expect("worker-thread refusal");
    }
    let display = HeadlessDisplay::new().expect("native display");
    let mut profiles =
        enzui_webkit::ffi::profile::ProfileStore::new("/unused-ephemeral-gpu-profile");
    let profile = enzui_webkit::web::WebProfile::ephemeral();
    let mut session = WebSession::new_profiled(&display, &mut profiles, &profile)
        .expect("attested native session");
    let mut router = ViewRouter::new();
    let view = router.create(41);
    let foreign = router.create(42);
    session.bind_view(&router, view).expect("bind view");
    session
        .resize_viewport(
            &router,
            view,
            ViewportSize::from_logical(320.0, 240.0).expect("viewport"),
        )
        .expect("resize");
    assert!(
        session.take_gpu_frame(&router, view).is_err(),
        "GPU presenter starts disabled"
    );
    session.enable_gpu_presentation();
    session.enable_gpu_presentation();
    reset_native_runtime_counters();
    session
        .load_html(
            "<style>html,body{margin:0;width:100%;height:100%;background:rgb(20,100,240)}</style>",
            "about:blank",
            10_000,
        )
        .expect("load real page");
    if std::env::args().any(|argument| argument == "--shared-buffer-lifecycle") {
        shared_buffer_lifecycle(session, &router, view);
        return;
    }
    if std::env::args().any(|argument| argument == "--completion-lifecycle") {
        completion_lifecycle(session, &display, &mut router, view);
        return;
    }
    if std::env::args().any(|argument| argument == "--owner-completion") {
        owner_completion(session, &router, view);
        return;
    }
    assert!(
        session.take_gpu_frame(&router, foreign).is_err(),
        "foreign view cannot steal a pending frame"
    );
    let first = matching(&session, &router, view, [20, 100, 240, 255]);
    first.presented();
    first.presented();
    evaluate(&session, "document.body.style.background='rgb(240,80,30)'");
    let second = matching(&session, &router, view, [240, 80, 30, 255]);
    assert_ne!(
        first.buffer_id(),
        second.buffer_id(),
        "simultaneously held native buffers have distinct identities"
    );
    second.presented();
    second.presented();
    evaluate(&session, "document.body.style.background='rgb(40,210,90)'");
    let third = matching(&session, &router, view, [40, 210, 90, 255]);
    assert_eq!(
        egl_probe::pixel(&first),
        [20, 100, 240, 255],
        "leased first frame must not be overwritten by later composition"
    );
    assert_eq!(
        egl_probe::pixel(&second),
        [240, 80, 30, 255],
        "leased second frame must remain stable"
    );
    third.presented();
    evaluate(&session, "document.body.style.background='rgb(100,40,190)'");
    session.pump(60);
    assert!(
        !session.gpu_frame_pending(),
        "three held buffers apply producer backpressure"
    );
    drop(second);
    let fourth = matching(&session, &router, view, [100, 40, 190, 255]);
    drop((third, fourth));
    let allocation_kind = std::fs::read_link(format!(
        "/proc/self/fd/{}",
        first.planes()[0].fd.as_raw_fd()
    ))
    .expect("leased descriptor kind");
    let before = allocation_descriptors(&allocation_kind);
    assert!(
        before > 0,
        "descriptor census includes the positively identified leased allocation"
    );
    let mut reused = std::collections::HashSet::new();
    for index in 0..24 {
        let colour = if index % 2 == 0 {
            [60, 120, 180, 255]
        } else {
            [180, 120, 60, 255]
        };
        evaluate(
            &session,
            &format!(
                "document.body.style.background='rgb({},{},{})'",
                colour[0], colour[1], colour[2]
            ),
        );
        let frame = matching(&session, &router, view, colour);
        reused.insert(frame.buffer_id());
        drop(frame);
    }
    assert!(
        reused.len() <= 4,
        "reused native allocations preserve identities for import caching"
    );
    session.pump(20);
    let after = allocation_descriptors(&allocation_kind);
    println!("DMA-BUF allocation descriptors before={before}, after={after}");
    assert!(
        after <= before + 4,
        "completed frames must return native allocations instead of leaking one per frame"
    );
    evaluate(&session, "document.body.style.background='rgb(200,190,40)'");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !session.gpu_frame_pending() {
        assert!(
            Instant::now() < deadline,
            "old generation has a pending compositor frame"
        );
        session.pump(2);
    }
    let replacement = router.recreate(view.slot());
    assert!(
        session.take_gpu_frame(&router, view).is_err(),
        "superseded generation refused"
    );
    session
        .bind_view(&router, replacement)
        .expect("bind replacement");
    assert!(
        session.take_gpu_frame(&router, view).is_err(),
        "old binding refused"
    );
    assert!(
        session
            .take_gpu_frame(&router, replacement)
            .expect("replacement frame state")
            .is_none(),
        "pending old generation is discarded"
    );
    evaluate(&session, "document.body.style.background='rgb(60,160,200)'");
    let last = next(&session, &router, replacement);
    assert_eq!(last.view(), replacement);
    let counters = native_runtime_counters();
    assert_eq!(
        counters.frame_copy_passes, 0,
        "GPU export performs no snapshot pixel copy"
    );
    assert_eq!(
        counters.snapshots_started, 0,
        "GPU export never requests snapshots"
    );
    let mut normal =
        WebSession::new(&display).expect("unregistered view keeps its normal presenter");
    normal
        .load_html(
            "<style>body{background:rgb(210,0,110)}</style>",
            "about:blank",
            10_000,
        )
        .expect("normal presenter page");
    let acknowledged = normal.acknowledged_frames();
    evaluate(&normal, "document.body.style.opacity='0.9'");
    let deadline = Instant::now() + Duration::from_secs(5);
    while normal.acknowledged_frames() <= acknowledged {
        assert!(
            Instant::now() < deadline,
            "normal presenter acknowledges compositor frames"
        );
        normal.pump(2);
    }
    evaluate(&normal, "document.body.style.opacity='1'");
    let snapshot = normal
        .snapshot(
            enzui_webkit::frame::Generation::FIRST,
            enzui_webkit::frame_plan::FrameSeq(0),
            10_000,
        )
        .expect("normal presenter snapshot");
    let offset = ((snapshot.height() / 2 * snapshot.width() + snapshot.width() / 2) * 4) as usize;
    assert_eq!(
        &snapshot.pixels()[offset..offset + 4],
        &[210, 0, 110, 255],
        "normal presenter paints its document"
    );
    assert!(
        native_runtime_counters().frame_copy_passes > 0,
        "snapshot is the positive control for the copy ledger"
    );
    assert!(
        native_runtime_counters().snapshots_started > 0,
        "snapshot request counter has a positive control"
    );
    drop(normal);
    session.terminate_web_process();
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.web_process_termination().is_none() {
        assert!(
            Instant::now() < deadline,
            "native renderer termination observed"
        );
        session.pump(2);
    }
    let recovered = session
        .recover_after_termination(&display, &mut profiles, &mut router, replacement)
        .expect("recover GPU session");
    assert!(!router.accepts(replacement));
    session
        .resize_viewport(
            &router,
            recovered,
            ViewportSize::from_logical(320.0, 240.0).expect("recovered viewport"),
        )
        .expect("recovered resize");
    session
        .load_html(
            "<style>html,body{margin:0;width:100%;height:100%;background:rgb(70,180,60)}</style>",
            "about:blank",
            10_000,
        )
        .expect("recovered document");
    let recovered_frame = matching(&session, &router, recovered, [70, 180, 60, 255]);
    drop(recovered_frame);
    drop(session);
    assert_eq!(
        egl_probe::pixel(&first),
        [20, 100, 240, 255],
        "buffer lease survives its session"
    );
    drop((first, last));

    println!(
        "GPU presentation probe completed: DMA-BUF export, EGL import, stable leases, discard, generation, zero snapshot copies"
    );
}
