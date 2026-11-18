//! Measure Rust allocations in the host IME poll on a real focused page.
//!
//! Build in release mode with `--features enzui-webkit/wpe`. Run on the process
//! main thread under a 2 GiB scope. `--require-zero` gates the scalar poll.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant};

use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::ime_bridge::NativeImeReport;
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::web::ViewRouter;

struct MeasuredAllocator;

thread_local! {
    static MEASUREMENT: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

fn allocation(bytes: usize) {
    let _ = MEASUREMENT.try_with(|cell| {
        if let Some((count, total)) = cell.get() {
            cell.set(Some((count + 1, total + bytes as u64)));
        }
    });
}

// SAFETY: all allocations and deallocations are forwarded unchanged to System.
#[allow(
    unsafe_code,
    reason = "GlobalAlloc instrumentation forwards System allocations without changing their ownership"
)]
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation(layout.size());
        // SAFETY: GlobalAlloc's caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation(layout.size());
        // SAFETY: GlobalAlloc's caller supplies a valid allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation(size);
        // SAFETY: the allocation and resize contract is inherited from the caller.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the allocation and layout are supplied by GlobalAlloc's caller.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn evaluate(session: &WebSession, source: &str) -> Result<String, Box<dyn Error>> {
    let id = session.evaluate_script(source, &ScriptWorld::Isolated("ime-probe".into()))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() >= deadline {
            return Err("script deadline".into());
        }
        session.pump(5);
        for event in session.take_page_events() {
            if let PageEvent::ScriptResult { id: found, result } = event
                && found == id
            {
                return result.map_err(|error| format!("script failed: {error:?}").into());
            }
        }
    }
}

fn matching_report(session: &WebSession) -> NativeImeReport {
    let full = session.page_ime_report().expect("installed IME context");
    let light = session
        .native_ime_report()
        .expect("installed native report");
    assert_eq!(
        light,
        NativeImeReport {
            focused: full.focused,
            caret: full.caret,
            purpose: full.purpose,
        }
    );
    light
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut require_zero = false;
    let mut text_bytes = 65536_usize;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--require-zero" => require_zero = true,
            "--bytes" => text_bytes = arguments.next().ok_or("missing text size")?.parse()?,
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    if !(1..=65536).contains(&text_bytes) {
        return Err("text size must be 1..=65536 bytes".into());
    }
    let display = HeadlessDisplay::new()?;
    let mut session = WebSession::new(&display)?;
    let mut router = ViewRouter::new();
    let view = router.create(1);
    session.bind_view(&router, view)?;
    assert!(session.native_ime_report().is_none());
    session.enable_input_method()?;
    assert!(!matching_report(&session).focused);
    session.load_html(
        &format!("<meta charset=utf-8><input id=edit style='width:800px;font:20px sans-serif'><input id=password type=password><script>edit.value='x'.repeat({text_bytes});edit.focus();edit.setSelectionRange({text_bytes},{text_bytes})</script>"),
        "about:blank",
        10_000,
    )?;
    session.focus_view();
    let deadline = Instant::now() + Duration::from_secs(5);
    let surrounding_bytes = loop {
        session.pump(10);
        let report = session.page_ime_report().unwrap();
        let length = report.surrounding.as_ref().map_or(0, |r| r.0.len());
        if report.focused && report.caret.is_some() && length >= text_bytes.min(1024) {
            break length;
        }
        assert!(
            Instant::now() < deadline,
            "page published focused surrounding text"
        );
    };
    let expected = matching_report(&session);
    let full = session.page_ime_report().unwrap();
    MEASUREMENT.with(|cell| cell.set(Some((0, 0))));
    let cloned = black_box(session.page_ime_report());
    let full_allocations = MEASUREMENT.with(|cell| cell.take().unwrap());
    assert!(full_allocations.0 > 0 && full_allocations.1 >= surrounding_bytes as u64);
    assert_eq!(cloned.unwrap().surrounding, full.surrounding);

    const ITERATIONS: u64 = 250_000;
    MEASUREMENT.with(|cell| cell.set(Some((0, 0))));
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        assert_eq!(black_box(session.native_ime_report()), Some(expected));
    }
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let (allocations, allocated_bytes) = MEASUREMENT.with(|cell| cell.take().unwrap());
    assert_eq!(
        session.page_ime_report().unwrap().surrounding,
        full.surrounding
    );
    if require_zero {
        assert_eq!(allocations, 0, "scalar poll cloned unused field text");
        assert_eq!(allocated_bytes, 0);
    }

    evaluate(
        &session,
        "globalThis.preeditSeen='';globalThis.compositionEnds=0;document.addEventListener('compositionupdate',event=>globalThis.preeditSeen=event.data);document.addEventListener('compositionend',()=>++globalThis.compositionEnds);true",
    )?;
    session.ime_set_preedit(&router, view, "かな", Some(6))?;
    session.pump(40);
    assert_eq!(
        session.page_ime_report().unwrap().preedit.unwrap().0,
        "かな"
    );
    assert_eq!(
        evaluate(&session, "globalThis.preeditSeen==='かな'")?,
        "true",
        "native preedit reached the DOM"
    );
    session.ime_cancel_preedit(&router, view)?;
    session.pump(80);
    assert_eq!(
        evaluate(
            &session,
            &format!(
                "globalThis.compositionEnds>0 && document.getElementById('edit').value.length==={text_bytes}"
            )
        )?,
        "true",
        "native cancellation reached the DOM without committing"
    );
    session.ime_commit(&router, view, "Z")?;
    session.pump(80);
    assert_eq!(
        evaluate(&session, "document.getElementById('edit').value.length")?,
        (text_bytes + 1).to_string()
    );
    assert!(matching_report(&session).focused);
    evaluate(&session, "document.getElementById('password').focus();true")?;
    session.pump(80);
    let password = matching_report(&session);
    assert!(password.focused);
    assert_eq!(
        password.purpose,
        enzui_webkit::web::ime::WEBKIT_INPUT_PURPOSE_PASSWORD
    );
    evaluate(&session, "document.activeElement.blur();true")?;
    session.pump(80);
    let blurred = matching_report(&session);
    assert!(!blurred.focused);
    assert!(blurred.caret.is_none());
    println!(
        "IME_REPORT_RESULT {{\"iterations\":{ITERATIONS},\"surrounding_bytes\":{surrounding_bytes},\"elapsed_ms\":{elapsed_ms},\"rust_allocations\":{allocations},\"rust_allocated_bytes\":{allocated_bytes},\"full_report_control_bytes\":{},\"require_zero\":{require_zero}}}",
        full_allocations.1
    );
    Ok(())
}
