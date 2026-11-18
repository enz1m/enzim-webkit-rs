//! Gesture-authorized copy and paste through the real page editor.
//!
//! Interactive hosts start a copy with [`WebSession::begin_page_copy`] and poll
//! before draining page events. Synchronous helpers pump the native context and
//! are intended for callers that can block. Text is bounded by the clipboard limit.

use super::*;

use crate::clipboard_route::{
    ClipboardDirection, ClipboardRouteError, HostGesture, HostPaste, PageCopy, authorize,
};
use crate::ffi::clipboard::{Clipboard, ClipboardError};
use crate::input::{InputEvent, KeyCode, Modifiers};

mod native_copy;

const COPY_DEADLINE_MS: u32 = 2_000;

/// The page's selected text, read for the host to copy through its own
/// clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSelection {
    /// The selection as plain text, at most
    /// [`MAX_CLIPBOARD_TEXT_BYTES`](crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES).
    pub text: String,
}

// Runs in its own world so the page cannot replace `getSelection`; the text
// crosses as `encodeURIComponent` output, plain ASCII inside a JSON string.
const SELECTION_SCRIPT: &str = "(function(){var a=document.activeElement,s=window.getSelection();var t=a&&typeof a.selectionStart==='number'?a.value.slice(a.selectionStart,a.selectionEnd):(s?String(s):'');return t.length>LIMIT?null:encodeURIComponent(t)})()";
const SELECTION_WORLD: &str = "enzui-host-selection";

fn decode_selection(json: &str) -> Option<Option<String>> {
    if json == "null" {
        return Some(None);
    }
    let encoded = json.strip_prefix('"')?.strip_suffix('"')?;
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut chars = encoded.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let hex = [chars.next()?, chars.next()?];
            bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok().map(Some)
}

/// An owner-thread copy request; poll before draining session page events.
///
/// No native references are borrowed. A changed view or document refuses
/// completion; focus is required at dispatch. A later copy supersedes it.
/// Hosts cancel the request when hiding its view. Dropping discards the result.
pub struct PendingPageCopy {
    view: crate::web::ViewId,
    owner: std::rc::Weak<crate::ffi::page::PageHub>,
    document: u64,
    intent: u64,
    serial: u64,
    display: *mut ffi::WPEDisplay,
    deadline: std::time::Instant,
    native: Option<crate::ffi::native_task::NativeTask<Result<PageSelection, ClipboardRouteError>>>,
    selection: Option<crate::page::PageRequestId>,
    finished: bool,
}

impl PendingPageCopy {
    /// Next stage timeout; hosts include it in their owner-loop wake deadline.
    pub fn deadline(&self) -> Option<std::time::Instant> {
        (!self.finished).then_some(self.deadline)
    }

    /// Cancel this accepted request without changing the system clipboard.
    /// Native input already dispatched cannot be recalled.
    pub fn cancel(&mut self) {
        if let Some(task) = &self.native {
            task.cancel();
        }
        self.finished = true;
    }

    /// Whether this request has completed or been cancelled.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Observe completion without pumping or waiting on the native event loop.
    ///
    /// Dispatch the owner context between polls. `None` means pending or already
    /// consumed; a completed result is returned once, within two seconds per stage.
    pub fn poll(
        &mut self,
        session: &WebSession,
        display: &HeadlessDisplay,
        router: &crate::web::ViewRouter,
    ) -> Option<Result<PageSelection, ClipboardRouteError>> {
        if self.finished {
            return None;
        }
        let result = self.advance(session, display, router)?;
        if let Some(task) = &self.native {
            task.cancel();
        }
        self.finished = true;
        Some(result)
    }

    fn advance(
        &mut self,
        session: &WebSession,
        display: &HeadlessDisplay,
        router: &crate::web::ViewRouter,
    ) -> Option<Result<PageSelection, ClipboardRouteError>> {
        let authorized = authorize(
            session.bound_view,
            router.accepts(self.view),
            self.view,
            ClipboardDirection::PageToHost,
            HostGesture::Present,
            None,
        );
        if let Err(error) = authorized {
            return Some(Err(error));
        }
        if self.serial != session.page_copy_serial.get()
            || self.display != display.as_ptr()
            || !self.owner.ptr_eq(&Rc::downgrade(&session.page_hub))
            || session.page_hub.load_state().0 != self.document
            || session.page_hub.navigation_intent() != self.intent
        {
            return Some(Err(ClipboardRouteError::PageDidNotCopy));
        }
        if let Some(task) = &self.native {
            return task.take_result().map(|result| {
                result
                    .map_err(native_copy::task_error)
                    .and_then(|result| result)
            });
        }
        if self.selection.is_none() {
            let limit = crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES;
            match session.evaluate_script(
                &SELECTION_SCRIPT.replace("LIMIT", &limit.to_string()),
                &crate::page::ScriptWorld::Isolated(SELECTION_WORLD.to_owned()),
            ) {
                Ok(id) => self.selection = Some(id),
                Err(error) => return Some(Err(ClipboardRouteError::Native(error.to_string()))),
            }
            self.deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(u64::from(COPY_DEADLINE_MS));
        }
        let id = self.selection?;
        if let Some(result) = session.page_hub.take_script_result(id) {
            return Some(
                result
                    .map_err(|error| ClipboardRouteError::Native(format!("{error:?}")))
                    .and_then(|json| selection_result(&json)),
            );
        }
        if std::time::Instant::now() >= self.deadline {
            return Some(Err(ClipboardRouteError::PageDidNotCopy));
        }
        None
    }
}

fn selection_result(json: &str) -> Result<PageSelection, ClipboardRouteError> {
    let limit = crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES;
    match decode_selection(json) {
        Some(Some(text)) if text.len() > limit => Err(ClipboardRouteError::TextTooLarge {
            size: text.len(),
            limit,
        }),
        Some(Some(text)) if !text.is_empty() => Ok(PageSelection { text }),
        Some(Some(_)) => Err(ClipboardRouteError::PageDidNotCopy),
        Some(None) => Err(ClipboardRouteError::TextTooLarge {
            size: limit + 1,
            limit,
        }),
        None => Err(ClipboardRouteError::Native(
            "the selection read returned an unexpected value".to_owned(),
        )),
    }
}

impl WebSession {
    /// Start a gesture-authorized copy without blocking the owner thread.
    ///
    /// Captures the exact native editor copy command, including trusted copy events. Backends
    /// without a clipboard fall back to an isolated selection read.
    /// Poll the returned request before draining page events.
    ///
    /// # Errors
    /// Refuses an unbound, foreign, stale, unfocused or gesture-free request,
    /// an unavailable native capture runtime, or rejected native admission.
    pub fn begin_page_copy(
        &self,
        display: &HeadlessDisplay,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        gesture: HostGesture,
    ) -> Result<PendingPageCopy, ClipboardRouteError> {
        authorize(
            self.bound_view,
            router.accepts(view),
            view,
            ClipboardDirection::PageToHost,
            gesture,
            None,
        )?;
        if !self.view_has_focus() {
            return Err(ClipboardRouteError::ViewNotFocused);
        }
        if self.page_hub.host_navigation_pending() {
            return Err(ClipboardRouteError::PageDidNotCopy);
        }
        let native = if Clipboard::for_display(display).is_ok() {
            Some(native_copy::begin(self)?)
        } else {
            None
        };
        let serial = self.page_copy_serial.get().wrapping_add(1);
        self.page_copy_serial.set(serial);
        Ok(PendingPageCopy {
            view,
            owner: Rc::downgrade(&self.page_hub),
            document: self.page_hub.load_state().0,
            intent: self.page_hub.navigation_intent(),
            serial,
            display: display.as_ptr(),
            deadline: std::time::Instant::now()
                + std::time::Duration::from_millis(u64::from(COPY_DEADLINE_MS)),
            native,
            selection: None,
            finished: false,
        })
    }

    /// Copy the page's current selection to the host clipboard.
    ///
    /// Pumps the native context while the exact Editor Copy command completes.
    /// Returns its owned text and the observed native clipboard write counters.
    /// This blocking helper requires the reviewed native copy capture runtime.
    ///
    /// # Errors
    ///
    /// [`ClipboardRouteError`]: the session is unbound, the command names
    /// another view, the generation is superseded, no host gesture backs it,
    /// the view has no input focus, capture is unavailable, the page produced
    /// no current text within the deadline, or the native result exceeded
    /// [`MAX_CLIPBOARD_TEXT_BYTES`](crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES).
    pub fn copy_page_selection_to_host(
        &self,
        display: &HeadlessDisplay,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        gesture: HostGesture,
    ) -> Result<PageCopy, ClipboardRouteError> {
        authorize(
            self.bound_view,
            router.accepts(view),
            view,
            ClipboardDirection::PageToHost,
            gesture,
            None,
        )?;
        if !self.view_has_focus() {
            return Err(ClipboardRouteError::ViewNotFocused);
        }
        let clip = Clipboard::for_display(display).map_err(native)?;
        let before = clip.change_count();
        let mut pending = self.begin_page_copy(display, router, view, gesture)?;
        let selection = loop {
            if let Some(result) = pending.poll(self, display, router) {
                break result?;
            }
            self.pump(1);
        };
        let after = clip.change_count();
        if after <= before {
            return Err(ClipboardRouteError::PageDidNotCopy);
        }
        Ok(PageCopy {
            text: selection.text,
            change_count_before: before,
            change_count_after: after,
        })
    }

    /// Read the focused page's selected text for the host to copy through its
    /// own clipboard, without the WPE display clipboard (an offscreen
    /// headless backend may have none).
    ///
    /// Gated like [`copy_page_selection_to_host`](Self::copy_page_selection_to_host):
    /// the router must accept `view` as this session's live binding, a host
    /// gesture must back the read, and the view must hold focus. The text is
    /// read in an isolated script world, bounded in size and time.
    ///
    /// # Errors
    ///
    /// The binding, liveness, gesture and focus refusals of the copy;
    /// [`ClipboardRouteError::PageDidNotCopy`] when nothing is selected or
    /// the page did not answer in time; [`ClipboardRouteError::TextTooLarge`]
    /// past the clipboard ceiling.
    pub fn read_page_selection(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        gesture: HostGesture,
    ) -> Result<PageSelection, ClipboardRouteError> {
        authorize(
            self.bound_view,
            router.accepts(view),
            view,
            ClipboardDirection::PageToHost,
            gesture,
            None,
        )?;
        if !self.view_has_focus() {
            return Err(ClipboardRouteError::ViewNotFocused);
        }
        let limit = crate::clipboard_route::MAX_CLIPBOARD_TEXT_BYTES;
        let script = SELECTION_SCRIPT.replace("LIMIT", &limit.to_string());
        let id = self
            .evaluate_script(
                &script,
                &crate::page::ScriptWorld::Isolated(SELECTION_WORLD.to_owned()),
            )
            .map_err(|error| ClipboardRouteError::Native(error.to_string()))?;
        let started = std::time::Instant::now();
        let result = loop {
            if let Some(result) = self.page_hub.take_script_result(id) {
                break result;
            }
            if started.elapsed() >= std::time::Duration::from_millis(u64::from(COPY_DEADLINE_MS)) {
                return Err(ClipboardRouteError::PageDidNotCopy);
            }
            self.pump(10);
        };
        let json = result.map_err(|error| ClipboardRouteError::Native(format!("{error:?}")))?;
        selection_result(&json)
    }

    /// Publish `text` on the host clipboard and paste it into the page's
    /// focused editable field with a real `Ctrl+V`.
    ///
    /// Fire-and-forget in the same sense as
    /// [`forward_input`](WebSession::forward_input): WebKit queues the chord
    /// and applies it on the main context, so a caller that wants to observe
    /// the DOM result pumps afterwards.
    ///
    /// # Errors
    ///
    /// [`ClipboardRouteError`]: the same binding/liveness/gesture refusals as
    /// [`copy_page_selection_to_host`](Self::copy_page_selection_to_host),
    /// plus [`ClipboardRouteError::TextTooLarge`] for an oversize payload
    /// (checked before any allocation), [`ClipboardRouteError::NotEnabled`]
    /// when the input-method seam is not installed, and
    /// [`ClipboardRouteError::NoFocusedField`] when no editable element holds
    /// DOM focus.
    pub fn paste_host_text_into_page(
        &self,
        display: &HeadlessDisplay,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        gesture: HostGesture,
        text: &str,
    ) -> Result<HostPaste, ClipboardRouteError> {
        authorize(
            self.bound_view,
            router.accepts(view),
            view,
            ClipboardDirection::HostToPage,
            gesture,
            Some(text.len()),
        )?;
        if !self.view_has_focus() {
            return Err(ClipboardRouteError::ViewNotFocused);
        }
        // A paste must land in a *field*, so the DOM focus state is load
        // bearing here in a way it is not for a copy (a selection can live in
        // ordinary document text). The IME seam is the session's only honest
        // source for that, so its absence is a refusal, not an assumption.
        let report = self
            .page_ime_report()
            .ok_or(ClipboardRouteError::NotEnabled)?;
        if !report.focused {
            return Err(ClipboardRouteError::NoFocusedField);
        }
        let clip = Clipboard::for_display(display).map_err(native)?;
        clip.set_text(text).map_err(|e| match e {
            ClipboardError::InteriorNul => ClipboardRouteError::InteriorNul,
            other => native(other),
        })?;
        let change_count = clip.change_count();
        self.page_copy_serial
            .set(self.page_copy_serial.get().wrapping_add(1));
        self.dispatch_chord(view, "v")?;
        Ok(HostPaste {
            bytes: text.len(),
            change_count,
        })
    }

    /// Send `Ctrl+<letter>` down/up as real WPE keyboard events.
    ///
    /// Rejection by [`forward_input`](WebSession::forward_input) is a typed
    /// error: that method is the last generation guard before WPE, so a
    /// refusal there means nothing reached the page and must not be reported
    /// as a completed clipboard hop.
    fn dispatch_chord(
        &self,
        view: crate::web::ViewId,
        letter: &str,
    ) -> Result<(), ClipboardRouteError> {
        let events = [
            InputEvent::KeyPressed {
                view,
                key: KeyCode::Character(letter.to_owned()),
                modifiers: Modifiers::CTRL,
            },
            InputEvent::KeyReleased {
                view,
                key: KeyCode::Character(letter.to_owned()),
                modifiers: Modifiers::CTRL,
            },
        ];
        for event in events {
            if !self.forward_input(&event) {
                return Err(ClipboardRouteError::Native(format!(
                    "WPE refused the Ctrl+{letter} chord for slot {}/gen {}",
                    view.slot(),
                    view.generation().0,
                )));
            }
        }
        Ok(())
    }
}

fn native(e: ClipboardError) -> ClipboardRouteError {
    ClipboardRouteError::Native(e.to_string())
}
