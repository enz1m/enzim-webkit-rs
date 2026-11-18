//! Renderer-independent protocol and policy types for embedded WPE WebKit.
//!
//! The module covers generation-keyed delivery, default-deny policy, profile isolation, bounded frame planning, focus, and IME ownership. Backend integrations perform the actual I/O and rendering.

pub mod cursor;
pub mod destination;
pub mod focus;
pub mod frame;
pub mod ime;
pub mod policy;
pub mod profile;
pub use enzui_security::redirect_capture;
pub mod view_id;

pub use cursor::{HIDDEN_CURSOR_SENTINEL, PageCursor, is_known_page_cursor, page_cursor};
pub use destination::{DestinationDenial, DestinationPolicy};
pub use focus::{
    FocusHandoff, HandoffOutcome, KeyTarget, PreeditCancel, PreeditOutcome, PreeditOwner, TabReply,
    Traversal,
};
pub use frame::{FrameBounds, FramePlan, FrameSeq, FrameVerdict};
pub use ime::{
    CaretRect, IME_TEXT_REDACTION, ImeClaim, ImeClose, PageIme, PageInput, Preedit, PublishedIme,
    Purpose, ToolkitImeEvent, diagnostic_ime_event, purpose_from_webkit, redacted_ime_text,
};
pub use policy::{
    CertContext, Decision, NavContext, PermissionKind, PolicyUrl, PopupContext, RequestId,
    RequestKind, ResolveOutcome, Scheme, WebPolicy,
};
pub use profile::{ProfileId, ProfileKind, WebProfile};
pub use redirect_capture::{RedirectCapture, RedirectCaptureError, RedirectKind};
pub use view_id::{Generation, ViewId, ViewRouter};

/// Identifies the backend used by a live web engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendKind {
    /// A real WPE WebKit process (`wpe-webkit-2.0`). Not built by this module.
    Wpe,
    /// A deterministic in-process test double selected explicitly by the caller.
    Mock,
}

impl BackendKind {
    /// Returns whether this backend is the in-process test double.
    #[must_use]
    pub const fn is_mock(self) -> bool {
        matches!(self, BackendKind::Mock)
    }
}
