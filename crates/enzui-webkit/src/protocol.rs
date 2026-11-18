//! The typed app↔engine protocol.
//!
//! One shared engine hosts many views. Every message in either direction
//! carries the [`ViewId`] it concerns, so the engine can multiplex views
//! without crossing their wires - a command for view A never acts on view B,
//! and an event from a crashed view A is tagged with A's *generation* so the
//! router discards it.
//!
//! This is the vocabulary only: no transport, no process, no `Task`. The
//! commands and events are plain data. The real WPE process consumes them
//! behind the `wpe` feature; the app side speaks this protocol against the mock
//! in exactly the same shape.

use std::fmt;

use crate::web::policy::{PolicyUrl, RequestKind};
use crate::web::{Decision, Generation, ViewId, WebProfile};

use crate::session::ViewRequestId;

/// A command the app sends to the engine.
///
/// Each variant that concerns an existing view names it by [`ViewId`], so a
/// stale command (built against a generation the engine already replaced) is
/// distinguishable from a live one. Its [`Debug`](fmt::Debug) implementation
/// redacts a navigation URL's userinfo, query, and fragment; the raw URL remains
/// available only by matching [`EngineCommand::Navigate`].
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineCommand {
    /// Create a view in `slot` on `profile`. The engine replies with
    /// [`EngineEvent::ViewCreated`] carrying the concrete [`ViewId`] (which
    /// stamps the generation).
    CreateView {
        /// The logical slot the view occupies.
        slot: u64,
        /// The data profile the view uses (its cookie/storage isolation).
        profile: WebProfile,
    },
    /// Ask `view` to navigate to `url`. Subject to the navigation policy; the
    /// engine will not act until the app resolves the correlated policy
    /// request.
    Navigate {
        /// The view to navigate.
        view: ViewId,
        /// The target URL.
        url: String,
    },
    /// The app's answer to a policy request the engine raised. Names the
    /// [`ViewRequestId`] it answers, so a reply for one request cannot satisfy
    /// another (correlation), and the request is view-scoped so a reply for a
    /// crashed view's request is rejected.
    ResolvePolicy {
        /// The correlated, view-scoped request being answered.
        request: ViewRequestId,
        /// The decision the app reached (typically produced by
        /// [`WebPolicy::resolve`](crate::web::WebPolicy::resolve)).
        decision: Decision,
    },
    /// Close `view`. The engine tears it down and the app must invalidate the
    /// view's outstanding policy requests
    /// ([`PolicySession::close_view`](crate::session::PolicySession::close_view)).
    CloseView {
        /// The view to close.
        view: ViewId,
    },
}

// A navigation may be a signed URL or carry another bearer value in its query
// or fragment. This command is displayed by the framework probe and is also a
// natural value for an app to include in protocol diagnostics. Keep the raw URL
// available to the engine, but route formatting through the same redacting URL
// type used by policy observations.
impl fmt::Debug for EngineCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateView { slot, profile } => f
                .debug_struct("CreateView")
                .field("slot", slot)
                .field("profile", profile)
                .finish(),
            Self::Navigate { view, url } => f
                .debug_struct("Navigate")
                .field("view", view)
                .field("url", &PolicyUrl::new(url.clone()).redacted())
                .finish(),
            Self::ResolvePolicy { request, decision } => f
                .debug_struct("ResolvePolicy")
                .field("request", request)
                .field("decision", decision)
                .finish(),
            Self::CloseView { view } => f.debug_struct("CloseView").field("view", view).finish(),
        }
    }
}

/// An event the engine sends to the app.
///
/// Every variant names the [`ViewId`] (hence generation) it came from, so the
/// app's [`ViewRouter`](crate::web::ViewRouter) can discard an event
/// from a superseded generation before it reaches the live view.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineEvent {
    /// A view was created (or recreated after a crash) at this concrete
    /// [`ViewId`].
    ViewCreated {
        /// The new view's id, carrying its generation.
        view: ViewId,
    },
    /// The engine needs a policy decision for `view`. Carries the
    /// [`RequestKind`] and the correlation id the app must quote back.
    PolicyRequest {
        /// The request, already tagged with its view and correlation id.
        request: ViewRequestId,
        /// What is being decided.
        kind: RequestKind,
    },
    /// A view crashed. The app must recreate it (advancing the generation) and
    /// invalidate every outstanding request that named the dead generation.
    ViewCrashed {
        /// The view that crashed, at the generation that died.
        view: ViewId,
    },
}

impl EngineEvent {
    /// The generation this event came from, for the router's staleness check.
    /// Every event is view-scoped, so this is always present.
    #[must_use]
    pub fn generation(&self) -> Generation {
        match self {
            EngineEvent::ViewCreated { view } | EngineEvent::ViewCrashed { view } => {
                view.generation()
            }
            EngineEvent::PolicyRequest { request, .. } => request.view().generation(),
        }
    }

    /// The view this event concerns.
    #[must_use]
    pub fn view(&self) -> ViewId {
        match self {
            EngineEvent::ViewCreated { view } | EngineEvent::ViewCrashed { view } => *view,
            EngineEvent::PolicyRequest { request, .. } => request.view(),
        }
    }
}
