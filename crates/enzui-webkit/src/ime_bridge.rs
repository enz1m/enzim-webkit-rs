//! The app-facing IME and cursor bridge between a native view and
//! `EnzWebView`.
//!

use crate::web::ToolkitImeEvent as ImeToolkitEvent;
use crate::web::{
    CaretRect, FocusHandoff, ImeClaim, ImeClose, PageIme, PageInput, PublishedIme, Purpose, ViewId,
    ViewRouter, page_cursor, purpose_from_webkit, redacted_ime_text,
};
use std::fmt;

/// One native input-method observation, in the engine's own vocabulary.
///
/// A plain value rather than the FFI report so that it exists feature-off and
/// so a test can state a page state without a live WebKit. Native polling copies
/// only these scalar fields, leaving surrounding text in the input context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeImeReport {
    /// Whether an editable element currently holds DOM focus.
    pub focused: bool,
    /// The caret rectangle in page view pixels, or `None` when the page has
    /// no caret (blurred, or never reported).
    pub caret: Option<(i32, i32, i32, i32)>,
    /// The raw `WebKitInputPurpose` for the focused field.
    pub purpose: i32,
}

/// What applying a native report did to the page's IME ownership.
///
/// Returned rather than swallowed so an application can show it and a test can
/// assert on it. `Unchanged` is distinct from `Updated` because "the caret moved"
/// and "nothing happened" must not look alike in a log.
#[derive(Debug, Clone, PartialEq)]
pub enum ImeTransition {
    /// The page took ownership of the window input method.
    Opened,
    /// The page already owned it and the caret/purpose moved.
    Updated,
    /// The report changed nothing.
    Unchanged,
    /// Ownership was released (blur, hide, crash, destruction).
    Closed(ImeClose),
    /// The claim was refused; the window input method is untouched.
    Refused(ImeClaim),
}

/// A page-directed IME action, decided but not yet performed.
///
/// The decision is separated from the FFI call for three reasons: an application
/// can render it, a feature-off build can exercise the whole decision path, and
/// the generation check happens before anything reaches WebKit.
#[derive(Clone, PartialEq, Eq)]
pub enum ImeEffect {
    /// Nothing to do (not the page's event, or refused).
    Ignored,
    /// Show this composition, with the caret at a byte offset into `text`
    /// (`None` = at the end). The byte→UTF-16 conversion WebKit needs happens
    /// at the engine boundary, in
    /// `crate::ffi::runtime::WebSession::ime_set_preedit`.
    SetPreedit {
        /// The composition text.
        text: String,
        /// Caret position as a byte offset into `text`.
        caret: Option<usize>,
    },
    /// Insert this text into the focused field.
    Commit(String),
    /// End the composition without inserting it.
    Cancel,
    /// The window closed the input method: drop the page's composition.
    Close,
}

impl fmt::Debug for ImeEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ignored => formatter.write_str("Ignored"),
            Self::SetPreedit { text, caret } => formatter
                .debug_struct("SetPreedit")
                .field("text", &redacted_ime_text(text))
                .field("caret", caret)
                .finish(),
            Self::Commit(text) => formatter
                .debug_tuple("Commit")
                .field(&redacted_ime_text(text))
                .finish(),
            Self::Cancel => formatter.write_str("Cancel"),
            Self::Close => formatter.write_str("Close"),
        }
    }
}

/// The app-facing IME/cursor state of one `EnzWebView`.
///
/// Owns the generation-checked [`PageIme`] and the page's requested cursor, and
/// converts in both directions. An application holds one per view, feeds it
/// native reports, hands [`Self::published`] to `EnzWebView::input_method`, and
/// feeds iced's IME events back through [`Self::route_event`].
#[derive(Debug, Default)]
pub struct WebViewIme {
    ime: PageIme,
    cursor: Option<String>,
}

impl WebViewIme {
    /// A view with no page IME and no page cursor request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The page's IME state, for `EnzWebView::input_method`.
    #[must_use]
    pub fn published(&self, router: &ViewRouter, view: ViewId) -> Option<PublishedIme> {
        self.ime.published(router, view)
    }

    /// The page's requested cursor name, for `EnzWebView::page_cursor`.
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Whether the requested cursor maps to a cursor iced knows.
    ///
    /// Unknown names still resolve (to the default), which is
    /// [`page_cursor`]'s contract; this reports whether the
    /// name was recognised so an application can say so.
    #[must_use]
    pub fn cursor_is_known(&self) -> bool {
        self.cursor
            .as_deref()
            .is_some_and(crate::web::is_known_page_cursor)
    }

    /// Record the page's requested cursor. `None` restores the host cursor.
    pub fn set_cursor(&mut self, name: Option<&str>) {
        self.cursor = name.map(ToOwned::to_owned);
        // Resolving here (and discarding) would be dead work; the widget
        // resolves. This assertion-free call documents that an unknown name is
        // *not* an error path.
        let _ = self.cursor.as_deref().map(page_cursor);
    }

    /// Apply one native observation.
    ///
    /// A report with no focus or no caret closes the IME: a page that
    /// blurred must not leave the window's input method open over stale
    /// geometry.
    pub fn apply_report(
        &mut self,
        router: &ViewRouter,
        view: ViewId,
        focus: &mut FocusHandoff,
        report: &NativeImeReport,
    ) -> ImeTransition {
        let Some((x, y, w, h)) = report.caret.filter(|_| report.focused) else {
            return self.close_transition(focus, ImeClose::FocusLost);
        };
        #[expect(
            clippy::cast_precision_loss,
            reason = "caret pixels; f32 is exact to 2^24 and a caret never gets there"
        )]
        let rect = match CaretRect::new(x as f32, y as f32, w as f32, h as f32) {
            Some(rect) => rect,
            // A non-finite/negative rectangle is refused rather than published:
            // an IME rectangle nobody can draw is worse than a closed IME.
            None => return self.close_transition(focus, ImeClose::FocusLost),
        };
        let purpose = purpose_from_webkit(report.purpose);
        let before = self.ime.published(router, view);
        match self.ime.claim(router, view, PageInput::new(rect, purpose)) {
            ImeClaim::Opened { .. } => ImeTransition::Opened,
            ImeClaim::Updated { .. } => {
                if before.map(|b| (b.input().caret, b.input().purpose)) == Some((rect, purpose)) {
                    ImeTransition::Unchanged
                } else {
                    ImeTransition::Updated
                }
            }
            refusal => ImeTransition::Refused(refusal),
        }
    }

    /// Close the page's IME for `reason` (hidden view, crash, destruction).
    ///
    /// Returns whether anything was actually open, so a caller can tell "closed
    /// it" from "already closed" without inspecting internals. The page's cursor
    /// request goes with it: a crashed or hidden page must not keep the host
    /// pointer overridden.
    pub fn close(&mut self, focus: &mut FocusHandoff, reason: ImeClose) -> bool {
        self.cursor = None;
        let was_open = self.ime.is_open();
        let _ = self.ime.close(focus, reason);
        was_open
    }

    /// `close`, reported as a transition.
    fn close_transition(&mut self, focus: &mut FocusHandoff, reason: ImeClose) -> ImeTransition {
        if self.close(focus, reason) {
            ImeTransition::Closed(reason)
        } else {
            ImeTransition::Unchanged
        }
    }

    /// Turn one of iced's window IME events into a page-directed effect.
    ///
    /// Refuses (with [`ImeEffect::Ignored`]) unless the page owns the window
    /// input method for a live `view` - the same
    /// [`PageIme::refuse_command`] check the engine's native emitters use, so a
    /// late event after focus loss, a generation change or crash recovery
    /// cannot type into a recreated page.
    #[must_use]
    pub fn route_event(
        &self,
        router: &ViewRouter,
        view: ViewId,
        event: &ImeToolkitEvent,
    ) -> ImeEffect {
        if self.ime.refuse_command(router, view).is_some() {
            return ImeEffect::Ignored;
        }
        match event {
            // `Opened` is the window acknowledging its own request; there is
            // nothing to push into the page.
            ImeToolkitEvent::Opened => ImeEffect::Ignored,
            ImeToolkitEvent::Preedit(text, selection) if text.is_empty() => {
                let _ = selection;
                ImeEffect::Cancel
            }
            ImeToolkitEvent::Preedit(text, selection) => ImeEffect::SetPreedit {
                text: text.clone(),
                // iced's range is byte-indexed; its END is the caret.
                caret: selection.as_ref().map(|r| r.end),
            },
            ImeToolkitEvent::Commit(text) => ImeEffect::Commit(text.clone()),
            ImeToolkitEvent::Closed => ImeEffect::Close,
        }
    }

    /// Apply the ownership consequence of an effect the caller performed.
    ///
    /// [`ImeEffect::Close`] is the one effect that also changes *ownership*:
    /// the window says the input method is gone, so the page's claim must go
    /// with it. Kept separate from [`Self::route_event`] so routing stays a
    /// pure decision.
    pub fn settle(&mut self, focus: &mut FocusHandoff, effect: &ImeEffect) {
        if matches!(effect, ImeEffect::Close) {
            self.close(focus, ImeClose::FocusLost);
        }
    }

    /// Whether the page currently owns the window input method.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.ime.is_open()
    }

    /// The view that owns the open input method, for a status line.
    #[must_use]
    pub fn owner(&self) -> Option<ViewId> {
        self.ime.owner()
    }

    /// The page's own on-the-spot composition (the *page* is composing, not the
    /// toolkit). Generation-checked, and arbitrated through `focus` so exactly
    /// one owner holds a preedit.
    pub fn set_preedit(
        &mut self,
        router: &ViewRouter,
        view: ViewId,
        focus: &mut FocusHandoff,
        preedit: crate::web::Preedit,
    ) -> ImeClaim {
        self.ime.set_preedit(router, view, focus, preedit)
    }

    /// Commit the page's composition.
    pub fn commit(
        &mut self,
        router: &ViewRouter,
        view: ViewId,
        focus: &mut FocusHandoff,
        text: &str,
    ) -> ImeClaim {
        self.ime.commit(router, view, focus, text)
    }

    /// Claim the window input method directly, for a caller that already has a
    /// [`PageInput`] (a stale-generation claim, for instance, which must be
    /// refused rather than opened).
    pub fn claim(&mut self, router: &ViewRouter, view: ViewId, input: PageInput) -> ImeClaim {
        self.ime.claim(router, view, input)
    }
}

/// The purpose a raw `WebKitInputPurpose` maps to, re-exported so an
/// application never writes a second mapping table.
#[must_use]
pub fn purpose_of(raw: i32) -> Purpose {
    purpose_from_webkit(raw)
}
