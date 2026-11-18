//! Main-thread native qualification of nonblocking page copy.
use enzui_webkit::clipboard_route::{ClipboardRouteError, HostGesture};
use enzui_webkit::ffi::Clipboard;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, PendingPageCopy, WebSession};
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::web::{ViewId, ViewRouter};
use std::time::{Duration, Instant};

#[path = "../../tests/support/clipboard_routes.rs"]
mod clipboard_routes;

fn evaluate(session: &WebSession, script: &str) -> String {
    let id = session
        .evaluate_script(script, &ScriptWorld::Page)
        .expect("script dispatch");
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        for event in session.take_page_events() {
            if let PageEvent::ScriptResult { id: found, result } = event
                && found == id
            {
                return result.expect("script success");
            }
        }
        assert!(Instant::now() < until, "script response deadline");
        session.pump(1);
    }
}

fn wait(
    mut pending: PendingPageCopy,
    session: &WebSession,
    display: &HeadlessDisplay,
    router: &ViewRouter,
) -> String {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(result) = pending.poll(session, display, router) {
            let text = result.expect("asynchronous copy completed").text;
            assert!(pending.is_finished());
            assert!(
                pending.poll(session, display, router).is_none(),
                "result consumed twice"
            );
            return text;
        }
        assert!(Instant::now() < until, "copy response deadline");
        session.pump(1);
    }
}

fn start(
    session: &WebSession,
    display: &HeadlessDisplay,
    router: &ViewRouter,
    view: ViewId,
) -> PendingPageCopy {
    let begin = Instant::now();
    let pending = session
        .begin_page_copy(display, router, view, HostGesture::Present)
        .expect("copy dispatch");
    let elapsed = begin.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "Copy blocked the UI for {elapsed:?}"
    );
    println!("Copy dispatch microseconds: {}", elapsed.as_micros());
    pending
}

fn shared_display_copy_diagnostic() {
    let display = HeadlessDisplay::new().expect("shared clipboard display");
    let mut router = ViewRouter::new();
    let view_a = router.create(29211);
    let view_b = router.create(29212);
    let mut a = WebSession::new(&display).expect("session A");
    let mut b = WebSession::new(&display).expect("session B");
    a.bind_view(&router, view_a).expect("bind A");
    b.bind_view(&router, view_b).expect("bind B");
    a.load_html("<p>Session A selection</p><script>document.addEventListener('copy',e=>{e.preventDefault();e.clipboardData.setData('text/plain','COPY-A')})</script>", "https://example.org/", 10000).expect("load A");
    b.load_html("<p>Session B selection</p><script>document.addEventListener('copy',e=>{const until=performance.now()+100;while(performance.now()<until){};e.preventDefault();e.clipboardData.setData('text/plain','COPY-B')})</script>", "https://example.org/", 10000).expect("load B");
    evaluate(&a, "getSelection().selectAllChildren(document.body);true");
    evaluate(&b, "getSelection().selectAllChildren(document.body);true");
    let clip = Clipboard::for_display(&display).expect("shared native clipboard");
    clip.set_text("SHARED-SENTINEL")
        .expect("seed shared clipboard");
    a.focus_view();
    a.evaluate_script(
        "const until=performance.now()+1000;while(performance.now()<until){};true",
        &ScriptWorld::Page,
    )
    .expect("delay A");
    let started = Instant::now();
    let _pending_a = start(&a, &display, &router, view_a);
    b.focus_view();
    let mut pending_b = start(&b, &display, &router, view_b);
    while started.elapsed() < Duration::from_millis(250) {
        a.pump(1);
        b.pump(1);
    }
    println!(
        "SHARED_COPY_EARLY={:?}",
        clip.read_text().expect("early clipboard")
    );
    while started.elapsed() < Duration::from_millis(1150) {
        a.pump(1);
        b.pump(1);
    }
    println!(
        "SHARED_COPY_LATE={:?}",
        clip.read_text().expect("late clipboard")
    );
    let result = pending_b.poll(&b, &display, &router);
    println!("SHARED_COPY_B_RESULT={result:?}");
    if std::env::args().any(|arg| arg == "--require-attribution") {
        let result = result
            .expect("B completion")
            .expect("B exact captured text");
        assert_eq!(
            result.text, "COPY-B",
            "B received another page's clipboard write"
        );
        println!("Shared display command attribution passed");
    }
}

fn same_page_copy_control() {
    let display = HeadlessDisplay::new().expect("same-page display");
    let mut session = WebSession::new(&display).expect("same-page session");
    let mut router = ViewRouter::new();
    let view = router.create(29213);
    session.bind_view(&router, view).expect("same-page bind");
    session.load_html("<p>Same page selection</p><script>window.copyN=0;document.addEventListener('copy',e=>{const n=++window.copyN;const until=performance.now()+(n===1?100:1000);while(performance.now()<until){};e.preventDefault();e.clipboardData.setData('text/plain',n===1?'FIRST-COPY':'SECOND-COPY')})</script>","https://example.org/",10000).expect("same-page fixture");
    session.focus_view();
    evaluate(
        &session,
        "getSelection().selectAllChildren(document.body);true",
    );
    let clip = Clipboard::for_display(&display).expect("same-page clipboard");
    clip.set_text("SAME-PAGE-SENTINEL").expect("same-page seed");
    let started = Instant::now();
    let mut old = start(&session, &display, &router, view);
    let mut new = start(&session, &display, &router, view);
    while started.elapsed() < Duration::from_millis(250) {
        session.pump(1);
    }
    assert_eq!(
        clip.read_text().expect("early same-page write").as_deref(),
        Some("FIRST-COPY"),
        "first native copy positive"
    );
    let early = new.poll(&session, &display, &router);
    assert!(
        early.is_none(),
        "new copy consumed earlier command's write: {early:?}"
    );
    assert_eq!(wait(new, &session, &display, &router), "SECOND-COPY");
    assert!(
        matches!(old.poll(&session, &display, &router), Some(Err(_))),
        "superseded same-page copy remained current"
    );
    println!("Same-page superseded command attribution passed");
}

fn accepted_blur_control() {
    let display = HeadlessDisplay::new().expect("blur display");
    let mut session = WebSession::new(&display).expect("blur session");
    let mut router = ViewRouter::new();
    let view = router.create(29214);
    session.bind_view(&router, view).expect("blur bind");
    session.load_html("<p>Blur selected text</p><script>window.copyN=0;document.addEventListener('copy',e=>{const n=++window.copyN;const until=performance.now()+200;while(performance.now()<until){};e.preventDefault();e.clipboardData.setData('text/plain',e.isTrusted?'BLUR-'+n:'UNTRUSTED')})</script>","https://example.org/",10000).expect("blur fixture");
    evaluate(
        &session,
        "getSelection().selectAllChildren(document.body);true",
    );
    for round in 1..=3 {
        session.focus_view();
        let pending = start(&session, &display, &router, view);
        session.blur_view();
        assert_eq!(
            wait(pending, &session, &display, &router),
            format!("BLUR-{round}")
        );
    }
    println!("Three immediate-blur trusted native copies passed");
}

fn unsupported_runtime_control() {
    let display = HeadlessDisplay::new().expect("unsupported display");
    let mut session = WebSession::new(&display).expect("unsupported session");
    let mut router = ViewRouter::new();
    let view = router.create(29215);
    session.bind_view(&router, view).expect("unsupported bind");
    session
        .load_html(
            "<p>Unsupported copy runtime</p>",
            "https://example.org/",
            10000,
        )
        .expect("unsupported fixture");
    session.focus_view();
    evaluate(
        &session,
        "getSelection().selectAllChildren(document.body);true",
    );
    let clip = Clipboard::for_display(&display).expect("clipboard exists");
    clip.set_text("UNSUPPORTED-RUNTIME-SENTINEL")
        .expect("unsupported sentinel");
    let before = clip.change_count();
    assert!(
        matches!(
            session.begin_page_copy(&display, &router, view, HostGesture::Present),
            Err(ClipboardRouteError::UnsupportedRuntime)
        ),
        "missing capture runtime did not refuse"
    );
    session.pump(100);
    assert_eq!(
        clip.change_count(),
        before,
        "unsupported runtime dispatched a copy"
    );
    assert_eq!(
        clip.read_text()
            .expect("unsupported preserved clipboard")
            .as_deref(),
        Some("UNSUPPORTED-RUNTIME-SENTINEL")
    );
    println!("Unsupported capture runtime refuses before clipboard effects passed");
}

fn blocking_shared_display_control() {
    let display = HeadlessDisplay::new().expect("blocking shared display");
    let mut a = WebSession::new(&display).expect("blocking A");
    let mut b = WebSession::new(&display).expect("blocking B");
    let mut router = ViewRouter::new();
    let va = router.create(29216);
    let vb = router.create(29217);
    a.bind_view(&router, va).expect("bind blocking A");
    b.bind_view(&router, vb).expect("bind blocking B");
    a.load_html("<p>A selected</p><script>document.addEventListener('copy',e=>{e.preventDefault();e.clipboardData.setData('text/plain','BLOCKING-A')})</script>","https://example.org/",10000).expect("blocking A fixture");
    b.load_html("<p>B selected</p><script>document.addEventListener('copy',e=>{const until=performance.now()+1000;while(performance.now()<until){};e.preventDefault();e.clipboardData.setData('text/plain','BLOCKING-B')})</script>","https://example.org/",10000).expect("blocking B fixture");
    evaluate(&a, "getSelection().selectAllChildren(document.body);true");
    evaluate(&b, "getSelection().selectAllChildren(document.body);true");
    let clip = Clipboard::for_display(&display).expect("blocking shared clipboard");
    clip.set_text("BLOCKING-SENTINEL").expect("blocking seed");
    a.focus_view();
    a.evaluate_script(
        "const until=performance.now()+500;while(performance.now()<until){};true",
        &ScriptWorld::Page,
    )
    .expect("delay A");
    let _a = start(&a, &display, &router, va);
    b.focus_view();
    let before = clip.change_count();
    let result = b
        .copy_page_selection_to_host(&display, &router, vb, HostGesture::Present)
        .expect("blocking exact B copy");
    assert_eq!(
        result.text, "BLOCKING-B",
        "blocking B consumed another page's earlier clipboard write"
    );
    assert_eq!(result.change_count_before, before);
    assert!(result.change_count_after > before);
    assert_eq!(result.change_count_after, clip.change_count());
    println!("Blocking shared-display exact source and actual counters passed");
}

fn main() {
    if std::env::args().any(|arg| arg == "--blocking-shared-display-control") {
        blocking_shared_display_control();
        return;
    }
    if std::env::args().any(|arg| arg == "--clipboard-route-control") {
        clipboard_routes::suite().expect("blocking clipboard route");
        println!("Blocking clipboard route suite passed");
        return;
    }
    if std::env::args().any(|arg| arg == "--unsupported-copy-runtime") {
        unsupported_runtime_control();
        return;
    }
    if std::env::args().any(|arg| arg == "--accepted-blur-control") {
        accepted_blur_control();
        return;
    }
    if std::env::args().any(|arg| arg == "--same-page-copy-control") {
        same_page_copy_control();
        return;
    }
    if std::env::args().any(|arg| arg == "--shared-display-copy-diagnostic") {
        shared_display_copy_diagnostic();
        return;
    }
    let display = HeadlessDisplay::new().expect("native display");
    let mut session = WebSession::new(&display).expect("native session");
    let mut router = ViewRouter::new();
    let view = router.create(29021);
    session.bind_view(&router, view).expect("bind");
    session.enable_input_method().expect("input method");
    session.load_html("<!doctype html><p id=body>Copy Ω selected body</p><input id=field value='Copy Ω input selection'>", "https://example.org/", 10000).expect("load fixture");
    session.focus_view();
    let fallback_only = std::env::args().any(|arg| arg == "--fallback-only");
    if fallback_only {
        assert!(
            Clipboard::for_display(&display).is_err(),
            "fallback needs a clipboard-free backend"
        );
    } else {
        let clip = Clipboard::for_display(&display).expect("native clipboard positive");
        clip.set_text("STALE HOST SENTINEL")
            .expect("seed clipboard");
    }

    evaluate(
        &session,
        "getSelection().selectAllChildren(document.querySelector('#body'));true",
    );
    if !fallback_only {
        let mut pending = start(&session, &display, &router, view);
        let mut foreign = WebSession::new(&display).expect("foreign native session");
        foreign
            .bind_view(&router, view)
            .expect("same live logical view in foreign owner");
        foreign
            .load_html(
                "<p>Foreign owner selection</p>",
                "https://example.org/",
                10000,
            )
            .expect("foreign document");
        foreign.focus_view();
        evaluate(
            &foreign,
            "getSelection().selectAllChildren(document.body);true",
        );
        let copied = start(&foreign, &display, &router, view);
        assert_eq!(
            wait(copied, &foreign, &display, &router),
            "Foreign owner selection"
        );
        assert!(
            matches!(pending.poll(&foreign, &display, &router), Some(Err(_))),
            "foreign session accepted a pending copy from another owner"
        );
        drop(foreign);
        session.focus_view();
        println!("Exact native session identity guard passed");
    }
    let pending = start(&session, &display, &router, view);
    assert_eq!(
        wait(pending, &session, &display, &router),
        "Copy Ω selected body"
    );
    assert!(matches!(
        session.begin_page_copy(&display, &router, view, HostGesture::Absent),
        Err(ClipboardRouteError::NoUserGesture { .. })
    ));
    session.blur_view();
    assert!(matches!(
        session.begin_page_copy(&display, &router, view, HostGesture::Present),
        Err(ClipboardRouteError::ViewNotFocused)
    ));
    session.focus_view();
    evaluate(
        &session,
        "getSelection().removeAllRanges();const field=document.querySelector('#field');field.focus();field.setSelectionRange(7,12);true",
    );
    let pending = start(&session, &display, &router, view);
    assert_eq!(wait(pending, &session, &display, &router), "input");
    println!("Body/input selection and gesture/focus start guards passed");
    if fallback_only {
        session
            .evaluate_script(
                "const until=performance.now()+1000;while(performance.now()<until){};true",
                &ScriptWorld::Page,
            )
            .expect("busy fallback script");
        let started = Instant::now();
        let mut pending = start(&session, &display, &router, view);
        let poll_started = Instant::now();
        assert!(pending.poll(&session, &display, &router).is_none());
        assert!(
            poll_started.elapsed() < Duration::from_millis(50),
            "fallback poll blocked"
        );
        assert_eq!(wait(pending, &session, &display, &router), "input");
        assert!(
            started.elapsed() >= Duration::from_millis(800),
            "fallback page was not busy"
        );
        println!("Clipboard-free isolated body/input fallback and busy dispatch passed");
        return;
    }
    evaluate(
        &session,
        "document.addEventListener('copy',e=>{e.preventDefault();e.clipboardData.setData('text/plain','Custom copy handler')});true",
    );
    session
        .evaluate_script(
            "const until=performance.now()+1000;while(performance.now()<until){};true",
            &ScriptWorld::Page,
        )
        .expect("busy script");
    let begin = Instant::now();
    let pending = start(&session, &display, &router, view);
    assert_eq!(
        wait(pending, &session, &display, &router),
        "Custom copy handler"
    );
    assert!(
        begin.elapsed() >= Duration::from_millis(800),
        "busy page was not actually busy"
    );
    println!("Busy-page real copy handler is asynchronous passed");
    evaluate(
        &session,
        "document.addEventListener('copy',()=>{const until=performance.now()+200;while(performance.now()<until){}});true",
    );
    let pending = start(&session, &display, &router, view);
    session.blur_view();
    assert_eq!(
        wait(pending, &session, &display, &router),
        "Custom copy handler",
        "Accepted copy was cancelled by ordinary window focus loss"
    );
    session.focus_view();
    println!("Accepted copy survives ordinary window defocus passed");
    let mut cancelled = start(&session, &display, &router, view);
    cancelled.cancel();
    session.pump(300);
    assert!(cancelled.is_finished());
    assert!(cancelled.poll(&session, &display, &router).is_none());
    let mut old = start(&session, &display, &router, view);
    let latest = start(&session, &display, &router, view);
    assert!(
        matches!(old.poll(&session, &display, &router), Some(Err(_))),
        "superseded copy accepted"
    );
    assert_eq!(
        wait(latest, &session, &display, &router),
        "Custom copy handler"
    );
    let mut pending = start(&session, &display, &router, view);
    session.begin_load_uri("about:blank").expect("navigation");
    assert!(
        matches!(pending.poll(&session, &display, &router), Some(Err(_))),
        "host navigation did not immediately cancel pending copy"
    );
    session.focus_view();
    assert!(
        matches!(
            session.begin_page_copy(&display, &router, view, HostGesture::Present),
            Err(ClipboardRouteError::PageDidNotCopy)
        ),
        "copy accepted while host navigation pending"
    );
    session.pump(300);
    assert!(pending.poll(&session, &display, &router).is_none());
    session
        .load_html("<p id=body>New document</p>", "https://example.org/", 10000)
        .expect("replacement document");
    session.focus_view();
    evaluate(
        &session,
        "getSelection().selectAllChildren(document.body);true",
    );
    session.take_page_events();
    let mut script_navigation = start(&session, &display, &router, view);
    session
        .evaluate_script(
            "location.href='https://example.invalid/clipboard-copy-test';true",
            &ScriptWorld::Page,
        )
        .expect("page-initiated navigation");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        session.pump(1);
        if session.take_page_events().iter().any(|event| {
            matches!(
                event,
                PageEvent::Load(enzui_webkit::page::LoadStage::Started)
            )
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "page-initiated load did not start"
        );
    }
    assert!(
        matches!(
            script_navigation.poll(&session, &display, &router),
            Some(Err(_))
        ),
        "page-initiated navigation completed a stale copy"
    );
    println!("Page-initiated navigation epoch guard passed");
    session.load_html("<p>Copy handler refuses selection fallback</p><script>document.addEventListener('copy',e=>e.preventDefault())</script>", "https://example.org/", 10000).expect("copy refusal document");
    session.focus_view();
    evaluate(
        &session,
        "getSelection().selectAllChildren(document.body);true",
    );
    let clip = Clipboard::for_display(&display).expect("clipboard");
    clip.set_text("COPY REFUSAL SENTINEL")
        .expect("refusal sentinel");
    let mut refused = start(&session, &display, &router, view);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(result) = refused.poll(&session, &display, &router) {
            assert!(
                matches!(result, Err(ClipboardRouteError::PageDidNotCopy)),
                "page copy refusal was bypassed: {result:?}"
            );
            break;
        }
        assert!(Instant::now() < until, "copy refusal did not finish");
        session.pump(1);
    }
    assert_eq!(
        clip.read_text().expect("refusal clipboard").as_deref(),
        Some("COPY REFUSAL SENTINEL")
    );
    println!("Page copy cancellation is not replaced by a selection fallback passed");
    let mut pending = start(&session, &display, &router, view);
    router.recreate(view.slot());
    assert!(matches!(
        pending.poll(&session, &display, &router),
        Some(Err(ClipboardRouteError::ViewNotLive { .. }))
    ));
    println!("Cancellation, supersession, navigation and generation guards passed");
}
