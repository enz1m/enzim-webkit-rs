//! Native main-thread copy, paste and refusal fixtures.

use std::time::Duration;

use enzui_webkit::clipboard_route::{
    ClipboardDirection, ClipboardRouteError, HostGesture, MAX_CLIPBOARD_TEXT_BYTES,
};
use enzui_webkit::ffi::Clipboard;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::input::{self, InputEvent};
use enzui_webkit::web::{ViewId, ViewRouter};

// The sentinel never appears in the fixture document.
const SENTINEL: &str = "HOST-SENTINEL-THE-PAGE-NEVER-COPIED-THIS";

fn field_page(value: &str) -> String {
    format!(
        // A '?' starts a URL query even inside a data URI's script.
        "data:text/html,<!doctype html><body><input id='t' value='{value}'><script>\
         var e=document.getElementById('t');\
         function r(){{var a='none';if(document.activeElement===e){{a='field';}}\
         document.title='cr:'+e.value+'|'+a;}}\
         e.addEventListener('input',r);e.addEventListener('focus',r);\
         e.addEventListener('blur',r);e.focus();e.select();r();\
         </script></body>"
    )
}

const NO_FIELD_PAGE: &str = "data:text/html,<!doctype html><body>\
    <p id='p'>no editable element here</p>\
    <script>document.title='cr:|none';</script></body>";

struct Fixture {
    session: WebSession,
    router: ViewRouter,
    view: ViewId,
}

fn open(display: &HeadlessDisplay, slot: u64, page: &str, ctx: &str) -> Result<Fixture, String> {
    let mut session = WebSession::new(display).map_err(|e| format!("{ctx}: new: {e}"))?;
    let mut router = ViewRouter::new();
    let view = router.create(slot);
    session
        .bind_view(&router, view)
        .map_err(|e| format!("{ctx}: bind: {e}"))?;
    session
        .enable_input_method()
        .map_err(|e| format!("{ctx}: enable_input_method: {e}"))?;
    session
        .load(page, 10_000)
        .map_err(|e| format!("{ctx}: load: {e}"))?;
    let focus = InputEvent::FocusGained {
        view,
        modifiers: input::Modifiers::NONE,
    };
    if !session.forward_input(&focus) || !session.view_has_focus() {
        return Err(format!("{ctx}: native FocusGained was not accepted"));
    }
    Ok(Fixture {
        session,
        router,
        view,
    })
}

fn reported_value(session: &WebSession) -> Result<Option<String>, String> {
    let Some(title) = session
        .page_title()
        .map_err(|error| format!("page title refused: {error}"))?
    else {
        return Ok(None);
    };
    let Some(rest) = title.strip_prefix("cr:") else {
        return Ok(None);
    };
    let Some((value, _active)) = rest.rsplit_once('|') else {
        return Ok(None);
    };
    Ok(Some(value.to_owned()))
}

fn wait_for_value(session: &WebSession, want: &str) -> Result<(), String> {
    let started = std::time::Instant::now();
    let mut last = None;
    while started.elapsed() < Duration::from_secs(3) {
        last = reported_value(session)?;
        if last.as_deref() == Some(want) {
            return Ok(());
        }
        session.pump(20);
    }
    Err(format!(
        "the page never reported field value {want:?}; last report {last:?}, \
         raw title {:?}",
        session.page_title()
    ))
}

fn wait_for_dom_field_focus(session: &WebSession) -> Result<(), String> {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        if session
            .page_ime_report()
            .ok_or("the IME seam reported nothing")?
            .focused
        {
            return Ok(());
        }
        session.pump(20);
    }
    Err("no editable element ever took DOM focus".to_owned())
}

fn seed_host_clipboard(display: &HeadlessDisplay) -> Result<i64, String> {
    let clip = Clipboard::for_display(display).map_err(|e| format!("clipboard: {e}"))?;
    clip.set_text(SENTINEL)
        .map_err(|e| format!("seed sentinel: {e}"))?;
    if clip.read_text().map_err(|e| e.to_string())?.as_deref() != Some(SENTINEL) {
        return Err("the sentinel seed did not take".to_owned());
    }
    Ok(clip.change_count())
}

fn host_clipboard_state(display: &HeadlessDisplay) -> Result<(i64, Option<String>), String> {
    let clip = Clipboard::for_display(display).map_err(|e| format!("clipboard: {e}"))?;
    let count = clip.change_count();
    let text = clip.read_text().map_err(|e| e.to_string())?;
    Ok((count, text))
}

fn copy_gates(display: &HeadlessDisplay) -> Result<(), String> {
    const PAYLOAD: &str = "enzui-wpe-page-selection";
    let page = field_page(PAYLOAD);
    let fx = open(display, 1, &page, "copy")?;
    wait_for_dom_field_focus(&fx.session)?;

    let seeded = seed_host_clipboard(display)?;

    let copied = fx
        .session
        .copy_page_selection_to_host(display, &fx.router, fx.view, HostGesture::Present)
        .map_err(|e| format!("copy refused: {e}"))?;
    if copied.text == SENTINEL {
        return Err(
            "the copy returned the host sentinel: it read the clipboard, \
                    it did not drive the page"
                .to_owned(),
        );
    }
    if copied.text != PAYLOAD {
        return Err(format!(
            "copy text mismatch: page held {PAYLOAD:?}, copy reported {:?}",
            copied.text
        ));
    }
    if copied.change_count_after <= copied.change_count_before {
        return Err(format!(
            "copy did not advance the clipboard: {} -> {}",
            copied.change_count_before, copied.change_count_after
        ));
    }
    let (count, text) = host_clipboard_state(display)?;
    if text.as_deref() != Some(PAYLOAD) {
        return Err(format!(
            "host clipboard holds {text:?}, expected the page's {PAYLOAD:?}"
        ));
    }
    if count <= seeded {
        return Err(format!(
            "host change-count did not advance past the seed: {seeded} -> {count}"
        ));
    }
    println!(
        "clip-route-1: page selection {PAYLOAD:?} reached the HOST clipboard \
         (count {} -> {count}), sentinel displaced OK",
        copied.change_count_before
    );

    let seeded = seed_host_clipboard(display)?;
    let empty = field_page("");
    let fx = open(display, 2, &empty, "copy-empty")?;
    wait_for_dom_field_focus(&fx.session)?;
    match fx
        .session
        .copy_page_selection_to_host(display, &fx.router, fx.view, HostGesture::Present)
    {
        Err(ClipboardRouteError::PageDidNotCopy) => {}
        Ok(copy) => {
            return Err(format!(
                "an empty selection must not produce a copy, got {copy:?}"
            ));
        }
        Err(other) => return Err(format!("expected PageDidNotCopy, got {other}")),
    }
    let (count, text) = host_clipboard_state(display)?;
    if count != seeded || text.as_deref() != Some(SENTINEL) {
        return Err(format!(
            "a refused copy disturbed the host clipboard: {seeded} -> {count}, {text:?}"
        ));
    }
    println!("clip-route-2: empty selection refused PageDidNotCopy, clipboard untouched OK");
    Ok(())
}

fn paste_gates(display: &HeadlessDisplay) -> Result<(), String> {
    let page = field_page("");
    let fx = open(display, 3, &page, "paste")?;
    wait_for_dom_field_focus(&fx.session)?;
    wait_for_value(&fx.session, "").map_err(|e| format!("paste precondition: {e}"))?;

    let first = "host-typed-alpha";
    let published = fx
        .session
        .paste_host_text_into_page(display, &fx.router, fx.view, HostGesture::Present, first)
        .map_err(|e| format!("paste refused: {e}"))?;
    if published.bytes != first.len() {
        return Err(format!(
            "published {published:?}, expected {} bytes",
            first.len()
        ));
    }
    wait_for_value(&fx.session, first)?;
    println!("clip-route-3a: host text {first:?} reached the focused DOM field OK");

    let second = "-beta";
    fx.session
        .paste_host_text_into_page(display, &fx.router, fx.view, HostGesture::Present, second)
        .map_err(|e| format!("second paste refused: {e}"))?;
    let expected = format!("{first}{second}");
    wait_for_value(&fx.session, &expected)?;
    println!("clip-route-3b: a second paste accumulated at the caret -> {expected:?} OK");

    let (before_count, before_text) = host_clipboard_state(display)?;
    let oversize = "z".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1);
    match fx.session.paste_host_text_into_page(
        display,
        &fx.router,
        fx.view,
        HostGesture::Present,
        &oversize,
    ) {
        Err(ClipboardRouteError::TextTooLarge { size, limit }) => {
            if size != MAX_CLIPBOARD_TEXT_BYTES + 1 || limit != MAX_CLIPBOARD_TEXT_BYTES {
                return Err(format!("oversize refusal misreported: {size} / {limit}"));
            }
        }
        other => return Err(format!("expected TextTooLarge, got {other:?}")),
    }
    let (after_count, after_text) = host_clipboard_state(display)?;
    if after_count != before_count || after_text != before_text {
        return Err(format!(
            "an oversize paste still published: {before_count} -> {after_count}"
        ));
    }
    if reported_value(&fx.session)?.as_deref() != Some(expected.as_str()) {
        return Err(format!(
            "an oversize paste changed the field to {:?}",
            reported_value(&fx.session)?
        ));
    }
    let at_limit = "y".repeat(MAX_CLIPBOARD_TEXT_BYTES);
    let ok = fx
        .session
        .paste_host_text_into_page(
            display,
            &fx.router,
            fx.view,
            HostGesture::Present,
            &at_limit,
        )
        .map_err(|e| format!("a paste of exactly the ceiling must be accepted, got {e}"))?;
    if ok.bytes != MAX_CLIPBOARD_TEXT_BYTES {
        return Err(format!("ceiling paste reported {ok:?}"));
    }
    println!(
        "clip-route-4: {} bytes accepted, +1 refused TextTooLarge with nothing published OK",
        MAX_CLIPBOARD_TEXT_BYTES
    );
    Ok(())
}

fn refusal_gates(display: &HeadlessDisplay) -> Result<(), String> {
    let page = field_page("guarded");
    let mut fx = open(display, 4, &page, "refusals")?;
    wait_for_dom_field_focus(&fx.session)?;
    wait_for_value(&fx.session, "guarded").map_err(|e| format!("refusal precondition: {e}"))?;

    let (count, text) = host_clipboard_state(display)?;
    match fx
        .session
        .copy_page_selection_to_host(display, &fx.router, fx.view, HostGesture::Absent)
    {
        Err(ClipboardRouteError::NoUserGesture {
            direction: ClipboardDirection::PageToHost,
        }) => {}
        other => {
            return Err(format!(
                "ungestured copy: expected NoUserGesture, got {other:?}"
            ));
        }
    }
    match fx.session.paste_host_text_into_page(
        display,
        &fx.router,
        fx.view,
        HostGesture::Absent,
        "should-never-arrive",
    ) {
        Err(ClipboardRouteError::NoUserGesture {
            direction: ClipboardDirection::HostToPage,
        }) => {}
        other => {
            return Err(format!(
                "ungestured paste: expected NoUserGesture, got {other:?}"
            ));
        }
    }
    let (count_after, text_after) = host_clipboard_state(display)?;
    if count_after != count || text_after != text {
        return Err("an ungestured command still touched the clipboard".to_owned());
    }
    if reported_value(&fx.session)?.as_deref() != Some("guarded") {
        return Err("an ungestured paste still changed the field".to_owned());
    }
    println!("clip-route-5: both directions refuse without a host gesture, nothing moved OK");

    let stale = fx.view;
    let _fresh = fx.router.recreate(stale.slot());
    for outcome in [
        fx.session
            .copy_page_selection_to_host(display, &fx.router, stale, HostGesture::Present)
            .map(|c| format!("{c:?}")),
        fx.session
            .paste_host_text_into_page(display, &fx.router, stale, HostGesture::Present, "x")
            .map(|p| format!("{p:?}")),
    ] {
        match outcome {
            Err(ClipboardRouteError::ViewNotLive { view }) if view == stale => {}
            other => {
                return Err(format!(
                    "stale generation: expected ViewNotLive, got {other:?}"
                ));
            }
        }
    }
    if reported_value(&fx.session)?.as_deref() != Some("guarded") {
        return Err("a stale-generation paste still changed the field".to_owned());
    }
    println!("clip-route-6: a superseded generation refuses both directions OK");

    let fx = open(display, 5, NO_FIELD_PAGE, "no-field")?;
    fx.session.pump(200);
    match fx.session.paste_host_text_into_page(
        display,
        &fx.router,
        fx.view,
        HostGesture::Present,
        "nowhere",
    ) {
        Err(ClipboardRouteError::NoFocusedField) => {}
        other => {
            return Err(format!(
                "no-field page: expected NoFocusedField, got {other:?}"
            ));
        }
    }
    println!("clip-route-7: a page with no editable element refuses NoFocusedField OK");
    Ok(())
}

pub(crate) fn suite() -> Result<(), String> {
    let display = HeadlessDisplay::new().expect("headless WPE display");
    copy_gates(&display)?;
    paste_gates(&display)?;
    refusal_gates(&display)?;
    Ok(())
}
