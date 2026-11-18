//! Generation-owned IME state for embedded pages.
//!
//! Claims, composition updates, publication, and host-to-page commands are checked against the live [`ViewId`]. [`PageIme::close`] is unconditional, preedit ownership is arbitrated by [`FocusHandoff`], and caret rectangles remain in logical view coordinates for the widget to map.

use crate::web::focus::{FocusHandoff, PreeditCancel, PreeditOutcome, PreeditOwner};
use crate::web::view_id::{Generation, ViewId, ViewRouter};
use std::fmt;

/// Text being composed by an input method, not yet committed.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Preedit {
    /// The composed text so far.
    pub content: String,
    /// The selected byte range of `content`, if the input method shows one.
    pub selection: Option<std::ops::Range<usize>>,
}

/// What kind of text a focused page field takes, as a hint to the input
/// method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Purpose {
    /// Ordinary text.
    #[default]
    Normal,
    /// A password or other secret: no prediction, no history.
    Secure,
    /// A terminal.
    Terminal,
}

/// An input-method event from the host toolkit, in the toolkit's order.
#[derive(Clone, PartialEq, Eq)]
pub enum ToolkitImeEvent {
    /// The input method opened.
    Opened,
    /// New composing text and its selected byte range; empty text clears it.
    Preedit(String, Option<std::ops::Range<usize>>),
    /// Text to insert.
    Commit(String),
    /// The input method closed.
    Closed,
}

/// Fixed replacement for IME text in diagnostics and diagnostic UI.
pub const IME_TEXT_REDACTION: &str = "[redacted]";

struct RedactedImeText<'a> {
    _text: &'a str,
}

impl fmt::Debug for RedactedImeText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(IME_TEXT_REDACTION)
    }
}

/// Returns a diagnostic value that never exposes the supplied IME text.
#[must_use]
pub fn redacted_ime_text(text: &str) -> impl fmt::Debug + '_ {
    RedactedImeText { _text: text }
}

struct RedactedPreedit<'a>(&'a Preedit);

impl fmt::Debug for RedactedPreedit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preedit")
            .field("content", &redacted_ime_text(&self.0.content))
            .field("selection", &self.0.selection)
            .finish()
    }
}

struct RedactedToolkitImeEvent<'a>(&'a ToolkitImeEvent);

impl fmt::Debug for RedactedToolkitImeEvent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ToolkitImeEvent::Opened => formatter.write_str("Opened"),
            ToolkitImeEvent::Preedit(text, selection) => formatter
                .debug_tuple("Preedit")
                .field(&redacted_ime_text(text))
                .field(selection)
                .finish(),
            ToolkitImeEvent::Commit(text) => formatter
                .debug_tuple("Commit")
                .field(&redacted_ime_text(text))
                .finish(),
            ToolkitImeEvent::Closed => formatter.write_str("Closed"),
        }
    }
}

// Composed text is the user's typing: Debug never prints it.
impl fmt::Debug for Preedit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RedactedPreedit(self).fmt(formatter)
    }
}

impl fmt::Debug for ToolkitImeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RedactedToolkitImeEvent(self).fmt(formatter)
    }
}

/// Returns a diagnostic view of a toolkit IME event with text redacted.
#[must_use]
pub fn diagnostic_ime_event(event: &ToolkitImeEvent) -> impl fmt::Debug + '_ {
    RedactedToolkitImeEvent(event)
}

/// A page caret rectangle in logical view pixels relative to the engine surface.
///
/// Page zoom is already reflected in these coordinates, but output scale is not. Map to window coordinates by translating through the viewport; do not divide by zoom or device scale.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaretRect {
    /// Distance from the surface's left edge, in view pixels.
    pub x: f32,
    /// Distance from the surface's top edge, in view pixels.
    pub y: f32,
    /// Caret width in view pixels. A collapsed caret is typically 0..2 px
    /// wide; zero is legal and must not be treated as "no caret".
    pub width: f32,
    /// Caret height in view pixels - the line height of the focused field.
    pub height: f32,
}

impl CaretRect {
    /// Constructs a caret rectangle, rejecting non-finite values and negative extents while allowing negative origins.
    #[must_use]
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Option<CaretRect> {
        if !x.is_finite() || !y.is_finite() || !width.is_finite() || !height.is_finite() {
            return None;
        }
        if width < 0.0 || height < 0.0 {
            return None;
        }
        Some(CaretRect {
            x,
            y,
            width,
            height,
        })
    }
}

/// WebKit’s ABI value for `WEBKIT_INPUT_PURPOSE_PASSWORD` in `WebKitInputPurpose`.
pub const WEBKIT_INPUT_PURPOSE_PASSWORD: i32 = 6;

/// Maps WebKit password purpose to [`Purpose::Secure`] and every other or unknown value to [`Purpose::Normal`].
#[must_use]
pub fn purpose_from_webkit(code: i32) -> Purpose {
    if code == WEBKIT_INPUT_PURPOSE_PASSWORD {
        Purpose::Secure
    } else {
        Purpose::Normal
    }
}

/// What the page reported about its focused field.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageInput {
    /// Where the caret is, in logical view pixels.
    pub caret: CaretRect,
    /// What kind of field it is, in iced's vocabulary.
    pub purpose: Purpose,
}

impl PageInput {
    /// A focused-field report.
    #[must_use]
    pub fn new(caret: CaretRect, purpose: Purpose) -> PageInput {
        PageInput { caret, purpose }
    }
}

/// The reason a page IME was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImeClose {
    /// The widget lost toolkit focus (Tab out, click away, window deactivate).
    FocusLost,
    /// The page blurred its own field without the widget losing focus.
    PageBlur,
    /// The WebProcess died; the page that owned the caret no longer exists.
    Crash,
    /// The view went hidden/clipped/offscreen, so no geometry is publishable.
    Hidden,
    /// The widget itself was destroyed.
    Destroyed,
    /// The engine asked the input method to reset (navigation, programmatic
    /// blur).
    Reset,
}

/// The result of a [`PageIme`] transition.
#[derive(Clone, PartialEq)]
pub enum ImeClaim {
    /// The IME was closed and is now open for `view`.
    Opened {
        /// The view that owns it.
        view: ViewId,
    },
    /// An already-open IME was updated (caret moved, purpose changed, preedit
    /// set) for the view that already owned it.
    Updated {
        /// The owning view.
        view: ViewId,
    },
    /// The composition was committed; the preedit is gone and the IME stays
    /// open for further input.
    Committed {
        /// The owning view.
        view: ViewId,
        /// The text the page must insert.
        text: String,
    },
    /// The IME is closed for `why`; closing an already closed IME returns the same outcome.
    Closed {
        /// Why.
        why: ImeClose,
    },
    /// The offered generation is no longer live; state is unchanged.
    RefusedStale {
        /// The generation the caller claimed.
        offered: Generation,
        /// The slot's actual live generation.
        live: Generation,
    },
    /// The named slot has no live view; state is unchanged.
    RefusedNoLiveView {
        /// The slot named.
        slot: u64,
    },
    /// A different live view owns the open IME.
    RefusedNotOwner {
        /// The view that owns the open IME.
        owner: ViewId,
        /// The view that tried to claim it.
        claimant: ViewId,
    },
    /// The toolkit owns the preedit, so page composition is refused.
    RefusedToolkitOwnsPreedit {
        /// The owner that already holds the preedit.
        incumbent: PreeditOwner,
    },
    /// The operation required an open IME, but none was open.
    NotOpen,
}

impl fmt::Debug for ImeClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opened { view } => formatter
                .debug_struct("Opened")
                .field("view", view)
                .finish(),
            Self::Updated { view } => formatter
                .debug_struct("Updated")
                .field("view", view)
                .finish(),
            Self::Committed { view, text } => formatter
                .debug_struct("Committed")
                .field("view", view)
                .field("text", &redacted_ime_text(text))
                .finish(),
            Self::Closed { why } => formatter.debug_struct("Closed").field("why", why).finish(),
            Self::RefusedStale { offered, live } => formatter
                .debug_struct("RefusedStale")
                .field("offered", offered)
                .field("live", live)
                .finish(),
            Self::RefusedNoLiveView { slot } => formatter
                .debug_struct("RefusedNoLiveView")
                .field("slot", slot)
                .finish(),
            Self::RefusedNotOwner { owner, claimant } => formatter
                .debug_struct("RefusedNotOwner")
                .field("owner", owner)
                .field("claimant", claimant)
                .finish(),
            Self::RefusedToolkitOwnsPreedit { incumbent } => formatter
                .debug_struct("RefusedToolkitOwnsPreedit")
                .field("incumbent", incumbent)
                .finish(),
            Self::NotOpen => formatter.write_str("NotOpen"),
        }
    }
}

/// A live-view-checked page IME state minted only by [`PageIme::published`].
#[derive(Clone, PartialEq)]
pub struct PublishedIme {
    view: ViewId,
    input: PageInput,
    preedit: Option<Preedit>,
}

impl fmt::Debug for PublishedIme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preedit = self.preedit.as_ref().map(RedactedPreedit);
        formatter
            .debug_struct("PublishedIme")
            .field("view", &self.view)
            .field("input", &self.input)
            .field("preedit", &preedit)
            .finish()
    }
}

impl PublishedIme {
    /// Returns the owning view; consumers should compare it with their current view id.
    #[must_use]
    pub fn view(&self) -> ViewId {
        self.view
    }

    /// The page's focused-field report.
    #[must_use]
    pub fn input(&self) -> PageInput {
        self.input
    }

    /// The active composition, if the page is composing.
    #[must_use]
    pub fn preedit(&self) -> Option<&Preedit> {
        self.preedit.as_ref()
    }
}

/// IME ownership, caret input, and composition state for one web view.
#[derive(Clone, Default)]
pub struct PageIme {
    // `None` means closed, and every refusal leaves this owner unchanged.
    owner: Option<ViewId>,
    input: Option<PageInput>,
    preedit: Option<Preedit>,
    last_close: Option<ImeClose>,
}

impl fmt::Debug for PageIme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preedit = self.preedit.as_ref().map(RedactedPreedit);
        formatter
            .debug_struct("PageIme")
            .field("owner", &self.owner)
            .field("input", &self.input)
            .field("preedit", &preedit)
            .field("last_close", &self.last_close)
            .finish()
    }
}

impl PageIme {
    /// A closed page IME.
    #[must_use]
    pub fn new() -> PageIme {
        PageIme::default()
    }

    /// Whether the page IME is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.owner.is_some()
    }

    /// The view that owns the open IME, if any.
    #[must_use]
    pub fn owner(&self) -> Option<ViewId> {
        self.owner
    }

    /// Why the IME last closed.
    #[must_use]
    pub fn last_close(&self) -> Option<ImeClose> {
        self.last_close
    }

    /// The active composition, if any.
    #[must_use]
    pub fn preedit(&self) -> Option<&Preedit> {
        self.preedit.as_ref()
    }

    fn refuse_if_not_live(router: &ViewRouter, view: ViewId) -> Option<ImeClaim> {
        match router.live_view(view.slot()) {
            None => Some(ImeClaim::RefusedNoLiveView { slot: view.slot() }),
            Some(live) if live.generation() != view.generation() => Some(ImeClaim::RefusedStale {
                offered: view.generation(),
                live: live.generation(),
            }),
            Some(_) => None,
        }
    }

    /// Opens the IME for a live `view`, or updates its caret and purpose when that view already owns it; stale views are refused.
    pub fn claim(&mut self, router: &ViewRouter, view: ViewId, input: PageInput) -> ImeClaim {
        if let Some(refusal) = Self::refuse_if_not_live(router, view) {
            return refusal;
        }
        match self.owner {
            Some(owner) if owner != view => ImeClaim::RefusedNotOwner {
                owner,
                claimant: view,
            },
            Some(_) => {
                self.input = Some(input);
                ImeClaim::Updated { view }
            }
            None => {
                self.owner = Some(view);
                self.input = Some(input);
                self.preedit = None;
                self.last_close = None;
                ImeClaim::Opened { view }
            }
        }
    }

    /// Sets page preedit only for the live owning view and only when toolkit preedit ownership does not conflict.
    pub fn set_preedit(
        &mut self,
        router: &ViewRouter,
        view: ViewId,
        handoff: &mut FocusHandoff,
        preedit: Preedit,
    ) -> ImeClaim {
        if let Some(refusal) = Self::refuse_if_not_live(router, view) {
            return refusal;
        }
        match self.owner {
            None => ImeClaim::NotOpen,
            Some(owner) if owner != view => ImeClaim::RefusedNotOwner {
                owner,
                claimant: view,
            },
            Some(_) => match handoff.page_claim_preedit() {
                PreeditOutcome::Refused { incumbent } => {
                    ImeClaim::RefusedToolkitOwnsPreedit { incumbent }
                }
                _ => {
                    self.preedit = Some(preedit);
                    ImeClaim::Updated { view }
                }
            },
        }
    }

    /// Commits composition text for the live owner, clears preedit, and leaves the IME open.
    pub fn commit(
        &mut self,
        router: &ViewRouter,
        view: ViewId,
        handoff: &mut FocusHandoff,
        text: impl Into<String>,
    ) -> ImeClaim {
        if let Some(refusal) = Self::refuse_if_not_live(router, view) {
            return refusal;
        }
        match self.owner {
            None => ImeClaim::NotOpen,
            Some(owner) if owner != view => ImeClaim::RefusedNotOwner {
                owner,
                claimant: view,
            },
            Some(_) => {
                let _ = handoff.commit_preedit();
                self.preedit = None;
                ImeClaim::Committed {
                    view,
                    text: text.into(),
                }
            }
        }
    }

    /// Unconditionally closes the IME, clears published state, and cancels preedit ownership through `handoff`.
    pub fn close(&mut self, handoff: &mut FocusHandoff, why: ImeClose) -> ImeClaim {
        let cancel = match why {
            ImeClose::FocusLost => PreeditCancel::FocusLost,
            ImeClose::PageBlur | ImeClose::Reset => PreeditCancel::Escape,
            ImeClose::Crash | ImeClose::Destroyed | ImeClose::Hidden => {
                PreeditCancel::ClickElsewhere
            }
        };
        let _ = handoff.cancel_preedit(cancel);
        self.owner = None;
        self.input = None;
        self.preedit = None;
        self.last_close = Some(why);
        ImeClaim::Closed { why }
    }

    /// Publishes state only when `view` is both the stored owner and the router’s current live view.
    #[must_use]
    pub fn published(&self, router: &ViewRouter, view: ViewId) -> Option<PublishedIme> {
        if Self::refuse_if_not_live(router, view).is_some() {
            return None;
        }
        let owner = self.owner?;
        if owner != view {
            return None;
        }
        Some(PublishedIme {
            view: owner,
            input: self.input?,
            preedit: self.preedit.clone(),
        })
    }

    /// Returns a refusal unless `view` is the live owner authorized to receive a host-to-page IME command.
    #[must_use]
    pub fn refuse_command(&self, router: &ViewRouter, view: ViewId) -> Option<ImeClaim> {
        if let Some(refusal) = Self::refuse_if_not_live(router, view) {
            return Some(refusal);
        }
        match self.owner {
            None => Some(ImeClaim::NotOpen),
            Some(owner) if owner != view => Some(ImeClaim::RefusedNotOwner {
                owner,
                claimant: view,
            }),
            Some(_) => None,
        }
    }
}
