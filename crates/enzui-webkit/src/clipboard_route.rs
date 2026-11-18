//! Session-level clipboard routing: the copy and paste commands a widget sends
//! and their typed outcomes.
//!

use crate::web::ViewId;

pub use crate::clipboard_bound::MAX_CLIPBOARD_TEXT_BYTES;

/// Which way text is moving across the page/host boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardDirection {
    /// The page's selection is copied out to the host clipboard.
    PageToHost,
    /// Host clipboard text is pasted into the page's focused field.
    HostToPage,
}

impl ClipboardDirection {
    /// A short human label for diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ClipboardDirection::PageToHost => "page→host copy",
            ClipboardDirection::HostToPage => "host→page paste",
        }
    }
}

/// Whether the host had a real user gesture (key chord, menu item, toolbar
/// button) behind this clipboard command.
///
/// [`HostGesture::Absent`] is a refusal, not a warning: an ungestured clipboard
/// hop is exactly what a hostile page would want the host to perform for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostGesture {
    /// A host-originated user action drove this command.
    Present,
    /// No host user action; the command is refused.
    Absent,
}

/// Why a session-level clipboard command was refused, or how it failed.
///
/// Exhaustive on purpose: each variant means something different happened to
/// the user's text, and a wildcard arm would let a future variant read as
/// success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardRouteError {
    /// The session is bound to no view, so a view-scoped clipboard command
    /// cannot be attributed to it.
    ViewNotBound,
    /// The command named a different view than this session's binding.
    ForeignSession {
        /// The id this session is bound to.
        bound: ViewId,
        /// The id the command named.
        asked: ViewId,
    },
    /// The named generation is no longer the router's live one.
    ViewNotLive {
        /// The id the command named.
        view: ViewId,
    },
    /// No host user gesture backed the command.
    NoUserGesture {
        /// The direction that was refused.
        direction: ClipboardDirection,
    },
    /// The host→page payload exceeds [`MAX_CLIPBOARD_TEXT_BYTES`]. Refused
    /// before any native allocation.
    TextTooLarge {
        /// The payload size that was offered, in bytes.
        size: usize,
        /// The ceiling that refused it.
        limit: usize,
    },
    /// The WPE view does not hold input focus, so a synthesized key gesture
    /// would not reach the page at all.
    ViewNotFocused,
    /// The input-method seam is not installed, so this session cannot tell
    /// whether an editable field holds focus. Refused rather than guessed.
    NotEnabled,
    /// No editable element holds focus in the page, so a paste has nowhere to
    /// land. Refused rather than dispatched, because WebKit would route it to
    /// whatever gains focus next.
    NoFocusedField,
    /// The host text held a NUL byte and cannot cross the C boundary.
    InteriorNul,
    /// No current bounded text was obtained from the accepted copy before its
    /// deadline, or its view/document was replaced. Previous clipboard data is
    /// never substituted for the command's own output.
    PageDidNotCopy,
    /// The runtime cannot attribute native page-copy output to its exact command.
    UnsupportedRuntime,
    /// A native clipboard call failed. Carries the native diagnostic.
    Native(String),
}

impl std::fmt::Display for ClipboardRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClipboardRouteError::ViewNotBound => write!(
                f,
                "clipboard command REFUSED: this session is bound to no view id"
            ),
            ClipboardRouteError::ForeignSession { bound, asked } => write!(
                f,
                "clipboard command REFUSED: this session is bound to slot {}/gen \
                 {}, the command named slot {}/gen {}",
                bound.slot(),
                bound.generation().0,
                asked.slot(),
                asked.generation().0
            ),
            ClipboardRouteError::ViewNotLive { view } => write!(
                f,
                "clipboard command REFUSED: slot {} generation {} is no longer \
                 live (the page was recreated); nothing was copied or pasted",
                view.slot(),
                view.generation().0
            ),
            ClipboardRouteError::NoUserGesture { direction } => write!(
                f,
                "clipboard command REFUSED: {} requires a host user gesture; an \
                 ungestured hop is never performed on a page's behalf",
                direction.label()
            ),
            ClipboardRouteError::TextTooLarge { size, limit } => write!(
                f,
                "clipboard paste REFUSED: {size} bytes exceeds the {limit}-byte \
                 ceiling; nothing was allocated or published"
            ),
            ClipboardRouteError::ViewNotFocused => write!(
                f,
                "clipboard command REFUSED: the WPE view does not hold input \
                 focus, so the key gesture would not reach the page"
            ),
            ClipboardRouteError::NotEnabled => write!(
                f,
                "clipboard command REFUSED: the input-method seam is not \
                 installed, so page field focus cannot be established"
            ),
            ClipboardRouteError::NoFocusedField => write!(
                f,
                "clipboard paste REFUSED: no editable element holds focus in the \
                 page"
            ),
            ClipboardRouteError::InteriorNul => write!(
                f,
                "clipboard paste REFUSED: the host text contains a NUL byte"
            ),
            ClipboardRouteError::PageDidNotCopy => write!(
                f,
                "page→host copy produced no current text within the deadline; \
                 previous clipboard contents are not reported as the copy"
            ),
            ClipboardRouteError::UnsupportedRuntime => {
                f.write_str("native command-scoped copy capture is unavailable")
            }
            ClipboardRouteError::Native(why) => {
                write!(f, "native clipboard call failed: {why}")
            }
        }
    }
}

impl std::error::Error for ClipboardRouteError {}

/// What a successful page→host copy moved.
///
/// The public [`Self::text`] remains the functional clipboard payload, but its
/// diagnostic representation is always `[redacted]`. Formatting this value or
/// an enclosing [`ClipboardOutcome`] therefore retains the change counters
/// without copying potentially private page text into logs or status history.
#[derive(Clone, PartialEq, Eq)]
pub struct PageCopy {
    /// The text the page put on the host clipboard.
    pub text: String,
    /// The clipboard change counter before the gesture.
    pub change_count_before: i64,
    /// The clipboard change counter after it - strictly greater, which is what
    /// makes this a fresh write rather than a stale read.
    pub change_count_after: i64,
}

impl std::fmt::Debug for PageCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageCopy")
            .field("text", &"[redacted]")
            .field("change_count_before", &self.change_count_before)
            .field("change_count_after", &self.change_count_after)
            .finish()
    }
}

/// What a successful host→page paste published and dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaste {
    /// How many bytes of host text were published to the clipboard.
    pub bytes: usize,
    /// The clipboard change counter after publication.
    pub change_count: i64,
}

/// The typed result of a session-level clipboard command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOutcome {
    /// The page copied out to the host clipboard.
    Copied(PageCopy),
    /// Host text was published and the paste gesture dispatched.
    Pasted(HostPaste),
    /// The command was refused or failed.
    Refused(ClipboardRouteError),
}

/// Authorize a clipboard command before any native work.
///
/// `payload_bytes` is `Some(n)` only for [`ClipboardDirection::HostToPage`];
/// a copy has no host payload to bound.
///
/// # Errors
///
/// The first check that fails, in the order documented on the module: binding,
/// liveness, gesture, then payload ceiling.
pub fn authorize(
    bound: Option<ViewId>,
    live: bool,
    asked: ViewId,
    direction: ClipboardDirection,
    gesture: HostGesture,
    payload_bytes: Option<usize>,
) -> Result<(), ClipboardRouteError> {
    match bound {
        None => return Err(ClipboardRouteError::ViewNotBound),
        Some(bound) if bound != asked => {
            return Err(ClipboardRouteError::ForeignSession { bound, asked });
        }
        Some(_) => {}
    }
    if !live {
        return Err(ClipboardRouteError::ViewNotLive { view: asked });
    }
    if gesture != HostGesture::Present {
        return Err(ClipboardRouteError::NoUserGesture { direction });
    }
    if let Some(size) = payload_bytes
        && size > MAX_CLIPBOARD_TEXT_BYTES
    {
        return Err(ClipboardRouteError::TextTooLarge {
            size,
            limit: MAX_CLIPBOARD_TEXT_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
