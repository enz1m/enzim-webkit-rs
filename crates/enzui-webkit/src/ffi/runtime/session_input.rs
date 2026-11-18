//! Private WebSession input dispatch and WPE key/button translation.
//!
//! The public methods remain inherent methods on `runtime::WebSession`; this
//! module is private so the split does not create a second API surface.

use super::*;

/// A button press and how many presses it completes. WebKit takes the count
/// with each press and makes a double click, a word selection or a
/// paragraph selection of it; a press reported as the first each time can
/// only ever be a single click.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Press {
    view: usize,
    button: u32,
    at: (f32, f32),
    time: std::time::Instant,
    count: u32,
}

impl Press {
    /// How soon a press must follow the one before to count with it.
    const INTERVAL: std::time::Duration = std::time::Duration::from_millis(400);
    /// How far from the one before it may land, in view-logical pixels.
    const REACH: f32 = 5.0;

    /// The press that follows `last`: one more of the same when it is the
    /// same button on the same view, soon enough and near enough.
    fn after(
        last: Option<Self>,
        view: usize,
        button: u32,
        at: (f32, f32),
        time: std::time::Instant,
    ) -> Self {
        let count = last
            .filter(|last| {
                last.view == view
                    && last.button == button
                    && time.saturating_duration_since(last.time) <= Self::INTERVAL
                    && (last.at.0 - at.0).abs() <= Self::REACH
                    && (last.at.1 - at.1).abs() <= Self::REACH
            })
            .map_or(1, |last| last.count.saturating_add(1));
        Self {
            view,
            button,
            at,
            time,
            count,
        }
    }
}

thread_local! {
    static LAST_PRESS: std::cell::Cell<Option<Press>> = const { std::cell::Cell::new(None) };
}

impl WebSession {
    /// Drive the default main context for roughly `duration_ms`.
    ///
    /// Dispatches ready callbacks and blocks in GLib when idle, with an owned
    /// deadline source bounding the wait. Timer granularity and individual
    /// callbacks may extend the budget. Setup failures use descriptor polling
    /// or bounded sleeping.
    /// This does not run a nested `GMainLoop`.
    pub fn pump(&self, duration_ms: u64) {
        let start = std::time::Instant::now();
        let cap = std::time::Duration::from_millis(duration_ms);
        if cap.is_zero() {
            return;
        }
        static POLL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let poll =
            *POLL.get_or_init(|| std::env::var_os("ENZUI_WPE_PUMP_POLL").is_none_or(|v| v != "0"));
        static BLOCKING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let blocking = poll
            && *BLOCKING.get_or_init(|| {
                std::env::var_os("ENZUI_WPE_PUMP_BLOCKING").is_none_or(|v| v != "0")
            });
        let deadline = blocking
            .then(|| super::super::threading::NativePumpDeadline::new(cap))
            .flatten();
        while start.elapsed() < cap {
            // SAFETY: a live deadline source bounds blocking on the default context.
            let dispatched = unsafe {
                ffi::g_main_context_iteration(ptr::null_mut(), i32::from(deadline.is_some()))
                    != ffi::G_FALSE
            };
            if !dispatched && deadline.is_none() {
                let remaining = cap.saturating_sub(start.elapsed());
                if !poll || super::super::threading::wait_native_events(remaining).is_err() {
                    std::thread::sleep(remaining.min(std::time::Duration::from_millis(2)));
                }
            }
        }
        // A frontend closed from its own UI has no other completion signal.
        self.check_inspector();
    }

    /// Forward a typed [`crate::input::InputEvent`] to the page through WPEPlatform.
    ///
    /// The event's coordinates are already logical view coordinates on the
    /// surface - the protocol layer ([`crate::input::ViewportMapping`])
    /// translated and clipped them before this event was built, so a pointer
    /// here is always in-bounds and at the right document position. The
    /// output/device scale is applied by WPE inside WebKit
    /// (`wpe_view_get_scale`), never doubled in here, so the same logical
    /// coordinate lands on the same DOM point at any output scale.
    /// This method does no geometry of its own; it only translates the typed
    /// event into a WPE event and dispatches it.
    ///
    /// Fire-and-forget: WebKit queues an accepted event and processes it on the
    /// main context, so call [`pump`](Self::pump) before snapshotting.
    ///
    /// Returns `false` without touching WPE unless the event names this
    /// session's exact bound [`ViewId`](crate::web::ViewId) or the id of its
    /// bound inspector frontend. The
    /// generation check deliberately lives at this last safe boundary: outer
    /// router checks are useful diagnostics, but cannot be the only guard.
    #[must_use]
    pub fn forward_input(&self, event: &crate::input::InputEvent) -> bool {
        use crate::input::InputEvent as Ev;

        // The page's own view, or the bound inspector frontend.
        let target = if self.bound_view == Some(event.view()) {
            self.wpe_view
        } else if let Some(frontend) = self.inspector_target(event.view()) {
            frontend
        } else {
            return false;
        };

        let mods = wpe_modifiers(event.modifiers());

        // Build the matching WPE event, dispatch it, and unref the reference.
        // SAFETY (applies to every arm): `target` is a borrowed but
        // live WPEView* (checked non-NULL at construction). Each
        // `wpe_event_*_new` returns a fresh event rc=1; `wpe_view_event` takes
        // its own reference; this code drops its own with `wpe_event_unref`. A NULL from
        // a constructor is a hard bug (bad arguments) and asserts.
        unsafe {
            match event {
                Ev::FocusGained { .. } => {
                    ffi::wpe_view_focus_in(target);
                }
                Ev::FocusLost { .. } => {
                    ffi::wpe_view_focus_out(target);
                }
                Ev::PointerMoved { at, .. } => {
                    let ev = ffi::wpe_event_pointer_move_new(
                        ffi::WPE_EVENT_POINTER_MOVE,
                        target,
                        ffi::WPE_INPUT_SOURCE_MOUSE,
                        0,
                        mods,
                        f64::from(at.x),
                        f64::from(at.y),
                        0.0,
                        0.0,
                    );
                    dispatch_and_unref(target, ev, "pointer_move");
                }
                Ev::PointerLeft { .. } => {
                    // WebKit maps a leave to a move outside the view at (-1, -1),
                    // as WPE's own Wayland seat sends it, so hover ends there.
                    let ev = ffi::wpe_event_pointer_move_new(
                        ffi::WPE_EVENT_POINTER_LEAVE,
                        target,
                        ffi::WPE_INPUT_SOURCE_MOUSE,
                        0,
                        mods,
                        -1.0,
                        -1.0,
                        0.0,
                        0.0,
                    );
                    dispatch_and_unref(target, ev, "pointer_leave");
                }
                Ev::PointerPressed { at, button, .. } => {
                    let button = wpe_button(*button);
                    // One pointer, so one record of its last press for the
                    // thread that owns the sessions.
                    let press = LAST_PRESS.with(|last| {
                        let press = Press::after(
                            last.get(),
                            target as usize,
                            button,
                            (at.x, at.y),
                            std::time::Instant::now(),
                        );
                        last.set(Some(press));
                        press
                    });
                    let ev = ffi::wpe_event_pointer_button_new(
                        ffi::WPE_EVENT_POINTER_DOWN,
                        target,
                        ffi::WPE_INPUT_SOURCE_MOUSE,
                        0,
                        mods,
                        button,
                        f64::from(at.x),
                        f64::from(at.y),
                        press.count, // never zero for a DOWN
                    );
                    dispatch_and_unref(target, ev, "pointer_down");
                }
                Ev::PointerReleased { at, button, .. } => {
                    let ev = ffi::wpe_event_pointer_button_new(
                        ffi::WPE_EVENT_POINTER_UP,
                        target,
                        ffi::WPE_INPUT_SOURCE_MOUSE,
                        0,
                        mods,
                        wpe_button(*button),
                        f64::from(at.x),
                        f64::from(at.y),
                        0, // press_count must be 0 for an UP
                    );
                    dispatch_and_unref(target, ev, "pointer_up");
                }
                Ev::WheelScrolled {
                    delta_x, delta_y, ..
                } => {
                    let ev = ffi::wpe_event_scroll_new(
                        target,
                        ffi::WPE_INPUT_SOURCE_MOUSE,
                        0,
                        mods,
                        f64::from(*delta_x),
                        f64::from(*delta_y),
                        ffi::G_TRUE,  // precise (pixel) deltas
                        ffi::G_FALSE, // not a scroll-stop
                        0.0,
                        0.0,
                    );
                    dispatch_and_unref(target, ev, "scroll");
                }
                Ev::WheelScrolledAt {
                    at,
                    delta_x,
                    delta_y,
                    unit,
                    ..
                } => {
                    let precise = match unit {
                        crate::input::ScrollUnit::Pixels => ffi::G_TRUE,
                        crate::input::ScrollUnit::Lines => ffi::G_FALSE,
                    };
                    let ev = ffi::wpe_event_scroll_new(
                        target,
                        ffi::WPE_INPUT_SOURCE_MOUSE,
                        0,
                        mods,
                        f64::from(*delta_x),
                        f64::from(*delta_y),
                        precise,
                        ffi::G_FALSE,
                        f64::from(at.x),
                        f64::from(at.y),
                    );
                    dispatch_and_unref(target, ev, "scroll");
                }
                Ev::KeyPressed { key, .. } => {
                    let (keycode, keyval) = wpe_key(key);
                    let ev = ffi::wpe_event_keyboard_new(
                        ffi::WPE_EVENT_KEYBOARD_KEY_DOWN,
                        target,
                        ffi::WPE_INPUT_SOURCE_KEYBOARD,
                        0,
                        mods,
                        keycode,
                        keyval,
                    );
                    dispatch_and_unref(target, ev, "key_down");
                }
                Ev::KeyReleased { key, .. } => {
                    let (keycode, keyval) = wpe_key(key);
                    let ev = ffi::wpe_event_keyboard_new(
                        ffi::WPE_EVENT_KEYBOARD_KEY_UP,
                        target,
                        ffi::WPE_INPUT_SOURCE_KEYBOARD,
                        0,
                        mods,
                        keycode,
                        keyval,
                    );
                    dispatch_and_unref(target, ev, "key_up");
                }
                Ev::TouchDown { seq, at, .. } => {
                    let ev = ffi::wpe_event_touch_new(
                        ffi::WPE_EVENT_TOUCH_DOWN,
                        target,
                        ffi::WPE_INPUT_SOURCE_TOUCHSCREEN,
                        0,
                        mods,
                        *seq,
                        f64::from(at.x),
                        f64::from(at.y),
                    );
                    dispatch_and_unref(target, ev, "touch_down");
                }
                Ev::TouchMoved { seq, at, .. } => {
                    let ev = ffi::wpe_event_touch_new(
                        ffi::WPE_EVENT_TOUCH_MOVE,
                        target,
                        ffi::WPE_INPUT_SOURCE_TOUCHSCREEN,
                        0,
                        mods,
                        *seq,
                        f64::from(at.x),
                        f64::from(at.y),
                    );
                    dispatch_and_unref(target, ev, "touch_move");
                }
                Ev::TouchUp { seq, at, .. } => {
                    let ev = ffi::wpe_event_touch_new(
                        ffi::WPE_EVENT_TOUCH_UP,
                        target,
                        ffi::WPE_INPUT_SOURCE_TOUCHSCREEN,
                        0,
                        mods,
                        *seq,
                        f64::from(at.x),
                        f64::from(at.y),
                    );
                    dispatch_and_unref(target, ev, "touch_up");
                }
                Ev::TouchCancel { seq, .. } => {
                    // The OS revoked a sequence. WPE has a dedicated event
                    // type so WebKit dispatches `touchcancel` to the page and
                    // ends its tracking of this identity. Position 0.0/0.0 is
                    // ignored by the cancel path in WebKit (the touch is
                    // finished by identity, not by position).
                    let ev = ffi::wpe_event_touch_new(
                        ffi::WPE_EVENT_TOUCH_CANCEL,
                        target,
                        ffi::WPE_INPUT_SOURCE_TOUCHSCREEN,
                        0,
                        mods,
                        *seq,
                        0.0,
                        0.0,
                    );
                    dispatch_and_unref(target, ev, "touch_cancel");
                }
            }
        }
        record_native_input();
        true
    }
}

/// Dispatch `event` to `view` and drop the reference. Panics loudly on a NULL
/// event (a constructor rejecting the arguments is a real bug, not a condition
/// to paper over).
///
/// # Safety
///
/// `event` must be a fresh `WPEEvent*` (rc=1) or NULL; `view` must be live.
unsafe fn dispatch_and_unref(view: *mut ffi::WPEView, event: *mut ffi::WPEEvent, what: &str) {
    assert!(
        !event.is_null(),
        "wpe_event constructor for {what} returned NULL — bad arguments"
    );
    // SAFETY: caller contract; view live, event fresh.
    unsafe {
        ffi::wpe_view_event(view, event);
        ffi::wpe_event_unref(event);
    }
}

/// Map the toolkit-mirrored [`Modifiers`](crate::input::Modifiers) bitset to
/// the `WPEModifiers` bitset the FFI consumes.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
/// (`WPE_MODIFIER_KEYBOARD_{CONTROL,SHIFT,ALT,META}` at bit positions 0..3).
pub(super) fn wpe_modifiers(m: crate::input::Modifiers) -> c_uint {
    let mut bits: c_uint = ffi::WPE_MODIFIER_NONE;
    if m.shift() {
        bits |= ffi::WPE_MODIFIER_KEYBOARD_SHIFT;
    }
    if m.ctrl() {
        bits |= ffi::WPE_MODIFIER_KEYBOARD_CONTROL;
    }
    if m.alt() {
        bits |= ffi::WPE_MODIFIER_KEYBOARD_ALT;
    }
    if m.meta() {
        bits |= ffi::WPE_MODIFIER_KEYBOARD_META;
    }
    if m.button1() {
        bits |= ffi::WPE_MODIFIER_POINTER_BUTTON1;
    }
    if m.button2() {
        bits |= ffi::WPE_MODIFIER_POINTER_BUTTON2;
    }
    if m.button3() {
        bits |= ffi::WPE_MODIFIER_POINTER_BUTTON3;
    }
    if m.button4() {
        bits |= ffi::WPE_MODIFIER_POINTER_BUTTON4;
    }
    if m.button5() {
        bits |= ffi::WPE_MODIFIER_POINTER_BUTTON5;
    }
    bits
}

/// Map the toolkit-mirrored [`PointerButton`](crate::input::PointerButton) to
/// the WPE 1-based button code.
fn wpe_button(button: crate::input::PointerButton) -> c_uint {
    use crate::input::PointerButton as B;
    match button {
        B::Primary => ffi::WPE_BUTTON_PRIMARY,
        B::Middle => ffi::WPE_BUTTON_MIDDLE,
        B::Secondary => ffi::WPE_BUTTON_SECONDARY,
        // An unknown raw button maps to its code directly; WPE tolerates
        // arbitrary button numbers.
        B::Other(code) => c_uint::from(code),
    }
}

/// Map a [`KeyCode`](crate::input::KeyCode) to a `(scancode, keysym)` pair for
/// `wpe_event_keyboard_new`.
///
/// Only the keys the tests exercise are given real scancodes; the rest fall
/// back to the keysym with a zero scancode, which WebKit still routes by
/// keyval. This is deliberately small - a full keymap is the engine's job, not
/// the FFI's.
fn wpe_key(key: &crate::input::KeyCode) -> (c_uint, c_uint) {
    use crate::input::KeyCode;
    match key {
        KeyCode::Character(s) if s == " " => (ffi::XKB_SCANCODE_SPACE, ffi::XKB_KEY_SPACE),
        KeyCode::Character(s) => {
            // Resolve the first scalar to its canonical XKB keysym.
            //
            // XKB keysyms coincide with the code point only for Latin-1
            // (U+0020..U+00FF); every other scalar has the Unicode-keysym form
            // `0x0100_0000 | code_point` (see `xkbcommon-keysyms.h`
            // `XKB_KEYSYM_UNICODE_OFFSET`). The raw code point happens to round
            // -trip through `xkb_keysym_to_utf32` for many values, but that is
            // a fallback, not a guarantee - a keysym like U+20AC's `0x20AC`
            // collides with the private-use keysym range. Emitting the
            // canonical form is what makes a non-ASCII key correct rather than
            // accidentally correct. Scancode 0 - WebKit routes by keyval.
            let cp = s.chars().next().map(|c| c as u32).unwrap_or(0);
            let keyval = unicode_to_keysym(cp);
            (0, keyval as c_uint)
        }
        KeyCode::Named(named) => (0, named_keysym(*named)),
    }
}

/// Map a routed [`NamedKey`](crate::input::NamedKey) to its canonical XKB
/// keysym. Scancode is 0 in every case - WebKit routes named keys by keysym.
///
/// # Source
///
/// Keysym values from `/usr/include/xkbcommon/xkbcommon-keysyms.h`. This is a
/// deliberate whitelist of the browser-relevant vocabulary declared by
/// `NamedKey`; a variant added later must add its keysym here or the
/// exhaustive match reddens compilation - the correct fail-loud shape.
pub(super) fn named_keysym(named: crate::input::NamedKey) -> c_uint {
    use crate::input::NamedKey as N;
    match named {
        N::Alt => 0xffe9,        // XKB_KEY_Alt_L
        N::AltGraph => 0xfe03,   // XKB_KEY_ISO_Level3_Shift
        N::CapsLock => 0xffe5,   // XKB_KEY_Caps_Lock
        N::Control => 0xffe3,    // XKB_KEY_Control_L
        N::NumLock => 0xff7f,    // XKB_KEY_Num_Lock
        N::ScrollLock => 0xff14, // XKB_KEY_Scroll_Lock
        N::Shift => 0xffe1,      // XKB_KEY_Shift_L
        N::Meta => 0xffe7,       // XKB_KEY_Meta_L
        N::Super => 0xffeb,      // XKB_KEY_Super_L
        N::Enter => 0xff0d,      // XKB_KEY_Return
        N::Tab => 0xff09,        // XKB_KEY_Tab
        N::Backspace => 0xff08,  // XKB_KEY_BackSpace
        N::Escape => 0xff1b,     // XKB_KEY_Escape
        N::Space => 0x0020,      // XKB_KEY_space
        N::ArrowUp => 0xff52,
        N::ArrowDown => 0xff54,
        N::ArrowLeft => 0xff51,
        N::ArrowRight => 0xff53,
        N::Home => 0xff50,
        N::End => 0xff57,
        N::PageUp => 0xff55,
        N::PageDown => 0xff56,
        N::Delete => 0xffff,      // XKB_KEY_Delete
        N::Insert => 0xff63,      // XKB_KEY_Insert
        N::ContextMenu => 0xff67, // XKB_KEY_Menu
        // Editing intents - XKB has dedicated function keysyms.
        N::Cut => 0x1008ff58,   // XKB_KEY_XF86Cut
        N::Copy => 0x1008ff57,  // XKB_KEY_XF86Copy
        N::Paste => 0x1008ff6d, // XKB_KEY_XF86Paste
        N::Undo => 0xff65,      // XKB_KEY_Undo
        N::Redo => 0xff66,      // XKB_KEY_Redo
        N::Clear => 0xff0b,
        N::Accept => 0xff0d,
        N::Again => 0xff66,
        N::Cancel => 0xff69,
        N::Execute => 0xff62,
        N::Find => 0xff68,
        N::Help => 0xff6a,
        N::Pause => 0xff13,
        N::Select => 0xff60,
        N::PrintScreen => 0xff61,
        N::BrowserBack => 0x1008ff26,
        N::BrowserForward => 0x1008ff27,
        N::BrowserRefresh => 0x1008ff29,
        N::BrowserStop => 0x1008ff28,
        N::BrowserSearch => 0x1008ff1b,
        N::BrowserFavorites => 0x1008ff30,
        N::BrowserHome => 0x1008ff18,
        N::ZoomIn => 0x1008ff8b,
        N::ZoomOut => 0x1008ff8c,
        // F1..F35 are contiguous XKB keysyms.
        N::F1 => 0xffbe,
        N::F2 => 0xffbf,
        N::F3 => 0xffc0,
        N::F4 => 0xffc1,
        N::F5 => 0xffc2,
        N::F6 => 0xffc3,
        N::F7 => 0xffc4,
        N::F8 => 0xffc5,
        N::F9 => 0xffc6,
        N::F10 => 0xffc7,
        N::F11 => 0xffc8,
        N::F12 => 0xffc9,
        N::F13 => 0xffca,
        N::F14 => 0xffcb,
        N::F15 => 0xffcc,
        N::F16 => 0xffcd,
        N::F17 => 0xffce,
        N::F18 => 0xffcf,
        N::F19 => 0xffd0,
        N::F20 => 0xffd1,
        N::F21 => 0xffd2,
        N::F22 => 0xffd3,
        N::F23 => 0xffd4,
        N::F24 => 0xffd5,
        N::F25 => 0xffd6,
        N::F26 => 0xffd7,
        N::F27 => 0xffd8,
        N::F28 => 0xffd9,
        N::F29 => 0xffda,
        N::F30 => 0xffdb,
        N::F31 => 0xffdc,
        N::F32 => 0xffdd,
        N::F33 => 0xffde,
        N::F34 => 0xffdf,
        N::F35 => 0xffe0,
    }
}

/// Map a Unicode scalar to its canonical XKB keysym.
///
/// * `U+0020..=U+00FF` (Latin-1): the keysym equals the code point - this
///   is the historical Latin-1 keysym block.
/// * Everything else: the Unicode-keysym form `0x0100_0000 | code_point`.
///
/// Control characters below `U+0020` have named keysyms of their own and are
/// not produced as `Character`; if one arrives this code still passes the raw value so
/// the mapping is total.
///
/// Source: `/usr/include/xkbcommon/xkbcommon-keysyms.h`
/// (`XKB_KEYSYM_UNICODE_OFFSET = 0x01000000`, and the Latin-1 keysym block).
pub(super) fn unicode_to_keysym(code_point: u32) -> u32 {
    match code_point {
        0x20..=0xFF => code_point,
        0x100..=0x10FFFF => 0x0100_0000 | code_point,
        other => other,
    }
}

#[cfg(test)]
mod press_tests {
    use super::Press;
    use std::time::{Duration, Instant};

    #[test]
    fn presses_in_one_place_in_quick_succession_count_up() {
        let start = Instant::now();
        let ms = |ms| start + Duration::from_millis(ms);
        let first = Press::after(None, 1, 1, (100.0, 50.0), ms(0));
        assert_eq!(first.count, 1);
        let second = Press::after(Some(first), 1, 1, (102.0, 51.0), ms(150));
        assert_eq!(second.count, 2);
        let third = Press::after(Some(second), 1, 1, (101.0, 50.0), ms(300));
        assert_eq!(third.count, 3);
        // Too late, too far, another button or another view starts again.
        assert_eq!(
            Press::after(Some(third), 1, 1, (101.0, 50.0), ms(900)).count,
            1
        );
        assert_eq!(
            Press::after(Some(second), 1, 1, (140.0, 50.0), ms(300)).count,
            1
        );
        assert_eq!(
            Press::after(Some(second), 1, 3, (101.0, 50.0), ms(300)).count,
            1
        );
        assert_eq!(
            Press::after(Some(second), 2, 1, (101.0, 50.0), ms(300)).count,
            1
        );
    }
}
