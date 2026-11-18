//! View-scoped policy sessions: a decision correlates to both the request and
//! the view generation that asked.
//!

use std::collections::BTreeMap;

use crate::web::policy::{RequestId, RequestKind};
use crate::web::{Decision, ResolveOutcome, ViewId, WebPolicy};

/// A correlation token that is also view-scoped.
///
/// Pairs the policy-local [`RequestId`] with the [`ViewId`] (generation
/// included) that raised it. Two requests never share this pair, and - unlike a
/// bare `RequestId` - a reply carrying it can be rejected the instant its view
/// is closed or superseded, because the [`ViewId`] carries the generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ViewRequestId {
    view: ViewId,
    request: RequestId,
}

impl ViewRequestId {
    /// The view (with generation) that raised this request.
    #[must_use]
    pub const fn view(self) -> ViewId {
        self.view
    }

    /// The policy-local correlation id.
    #[must_use]
    pub const fn request(self) -> RequestId {
        self.request
    }
}

/// The outcome of resolving a view-scoped policy request.
///
/// Distinguishes three cases that must never be conflated:
///
/// * a genuine [`Decision`] for a still-live view;
/// * the view is gone (closed or superseded by a newer generation) - the
///   reply authorises nothing;
/// * the id is unknown to the policy (never opened, or already resolved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionResolve {
    /// The request was outstanding on a live view and is now decided.
    Decided {
        /// The request that was resolved.
        id: ViewRequestId,
        /// The decision reached.
        decision: Decision,
    },
    /// The request named a view that is no longer live (closed, or a newer
    /// generation replaced it). No decision - a crashed view's late reply
    /// cannot authorise the view that replaced it. This is the load-bearing
    /// view-scoping guard.
    ViewGone {
        /// The stale request that was rejected.
        id: ViewRequestId,
    },
    /// The id names no outstanding policy request (never opened, or already
    /// resolved). Distinct from `ViewGone`: the correlation itself failed.
    Unknown {
        /// The unrecognised request.
        id: ViewRequestId,
    },
}

impl SessionResolve {
    /// The decision, if one was reached. `None` for `ViewGone`/`Unknown`, so a
    /// caller cannot accidentally treat a rejected reply as an allow.
    #[must_use]
    pub const fn decision(self) -> Option<Decision> {
        match self {
            SessionResolve::Decided { decision, .. } => Some(decision),
            SessionResolve::ViewGone { .. } | SessionResolve::Unknown { .. } => None,
        }
    }
}

/// A [`WebPolicy`] whose outstanding requests are scoped to the view that
/// raised them.
///
/// Wraps one policy and a live-view table. Opening a request records which
/// [`ViewId`] raised it; resolving a request rejects it unless that exact
/// [`ViewId`] (generation included) is still the live one for its slot.
#[derive(Debug, Clone)]
pub struct PolicySession {
    policy: WebPolicy,
    /// The live generation per slot. A request whose view is not the current
    /// live view for its slot is rejected on resolve. Mirrors the frame
    /// router's `slot -> generation` map - same staleness concept, not a new
    /// one.
    live: BTreeMap<u64, ViewId>,
    /// Which view raised each outstanding policy request, so a resolve can be
    /// judged view-scoped even after the policy would still accept the bare id.
    request_view: BTreeMap<RequestId, ViewId>,
}

impl PolicySession {
    /// A fresh session over `policy` with no live views.
    #[must_use]
    pub fn new(policy: WebPolicy) -> PolicySession {
        PolicySession {
            policy,
            live: BTreeMap::new(),
            request_view: BTreeMap::new(),
        }
    }

    /// Register `view` as the live view for its slot.
    ///
    /// Recording a newer generation for a slot supersedes the older one:
    /// any request the older generation left outstanding will now resolve to
    /// [`SessionResolve::ViewGone`]. This is how crash-recreate invalidates the
    /// dead view's requests.
    pub fn open_view(&mut self, view: ViewId) {
        self.live.insert(view.slot(), view);
    }

    /// Whether `view` is the live view for its slot right now.
    #[must_use]
    pub fn is_live(&self, view: ViewId) -> bool {
        self.live.get(&view.slot()) == Some(&view)
    }

    /// Close `view`: it is no longer live, and its outstanding policy
    /// requests are invalidated.
    ///
    /// Only closes the view if it is *currently* the live one for its slot - a
    /// stale close (naming a generation already superseded) is a no-op, so it
    /// cannot tear down the view that replaced it. Returns how many outstanding
    /// requests were dropped, so a caller can log the cleanup. `0` is a valid,
    /// literal count (a view with nothing pending).
    pub fn close_view(&mut self, view: ViewId) -> usize {
        if self.live.get(&view.slot()) != Some(&view) {
            // Stale or unknown close - do not disturb whoever is live now.
            return 0;
        }
        self.live.remove(&view.slot());
        self.invalidate_requests_of(view)
    }

    /// The number of outstanding requests for `view` still pending.
    #[must_use]
    pub fn outstanding_for(&self, view: ViewId) -> usize {
        self.request_view
            .iter()
            .filter(|&(id, &v)| v == view && self.policy.is_outstanding(*id))
            .count()
    }

    /// Total outstanding policy requests across all views.
    #[must_use]
    pub fn outstanding_count(&self) -> usize {
        self.policy.outstanding_count()
    }

    /// Open a policy request raised by `view`, returning its view-scoped
    /// correlation id.
    ///
    /// The returned [`ViewRequestId`] carries `view`, so if `view` is later
    /// closed or superseded the reply is rejected. The request is only tracked
    /// as belonging to a live view; opening against a view that is not live is
    /// still allowed (the engine may race), but it will resolve to
    /// [`SessionResolve::ViewGone`] until/unless that view becomes live.
    pub fn open(&mut self, view: ViewId, kind: RequestKind) -> ViewRequestId {
        let request = self.policy.open(kind);
        self.request_view.insert(request, view);
        ViewRequestId { view, request }
    }

    /// Resolve a view-scoped request.
    ///
    /// The order of checks is the security contract:
    ///
    /// 1. View-scope first. If `id.view` is not the live view for its slot,
    ///    the reply is [`SessionResolve::ViewGone`] and the underlying policy
    ///    request is dropped without being decided - a crashed view's late
    ///    reply authorises nothing. This check comes *before* the policy is
    ///    consulted, so a stale reply never reaches the decision code.
    /// 2. Correlation. Otherwise the bare id is resolved by the policy,
    ///    which enforces that the reply names an outstanding request; an unknown
    ///    id is [`SessionResolve::Unknown`].
    pub fn resolve(&mut self, id: ViewRequestId) -> SessionResolve {
        // (1) View-scope guard, BEFORE consulting the policy. A reply for a
        // view that is no longer live decides nothing, and this code drops the stranded
        // request so it cannot linger.
        if !self.is_live(id.view) {
            // Drop the underlying request if it is still sitting in the policy,
            // so a later (also-stale) reply can't find it either.
            self.request_view.remove(&id.request);
            self.discard_underlying(id.request);
            return SessionResolve::ViewGone { id };
        }
        // Also reject if the request was recorded against a DIFFERENT view than
        // the one the reply claims - a reply must name the view that raised it,
        // not merely a currently-live view.
        match self.request_view.get(&id.request) {
            Some(&recorded) if recorded == id.view => {}
            Some(_) | None => {
                // Either recorded against another view, or never recorded here.
                // Consult the policy only to report Unknown consistently.
                self.request_view.remove(&id.request);
                return match self.policy.resolve(id.request) {
                    // The policy knew the id but this code does not trust the view claim:
                    // treat as ViewGone (a reply must name its own view).
                    ResolveOutcome::Decided { .. } => SessionResolve::ViewGone { id },
                    ResolveOutcome::Unknown { .. } => SessionResolve::Unknown { id },
                };
            }
        }

        // (2) Correlation via the underlying policy.
        self.request_view.remove(&id.request);
        match self.policy.resolve(id.request) {
            ResolveOutcome::Decided { decision, .. } => SessionResolve::Decided { id, decision },
            ResolveOutcome::Unknown { .. } => SessionResolve::Unknown { id },
        }
    }

    /// Invalidate every outstanding request raised by `view`, dropping them from
    /// the policy so none can later be resolved. Returns the count dropped.
    fn invalidate_requests_of(&mut self, view: ViewId) -> usize {
        let ids: Vec<RequestId> = self
            .request_view
            .iter()
            .filter(|&(_, &v)| v == view)
            .map(|(&id, _)| id)
            .collect();
        let mut dropped = 0;
        for id in ids {
            self.request_view.remove(&id);
            if self.discard_underlying(id) {
                dropped += 1;
            }
        }
        dropped
    }

    /// Remove `request` from the underlying policy without deciding it, so it
    /// can never be resolved. Returns whether it was actually outstanding.
    fn discard_underlying(&mut self, request: RequestId) -> bool {
        if self.policy.is_outstanding(request) {
            // `resolve` consumes the request; this code throws the decision away. This
            // preserves the "invalidate, don't decide" rule.
            let _ = self.policy.resolve(request);
            true
        } else {
            false
        }
    }

    /// The number of entries in the internal request-view tracking map.
    ///
    /// Every `open` inserts one entry; every `resolve`, `close_view`, and
    /// `invalidate_requests_of` path must remove it. A non-zero value after
    /// all requests are resolved or invalidated is a tracking-map leak.
    #[cfg(test)]
    #[must_use]
    pub fn tracking_entries(&self) -> usize {
        self.request_view.len()
    }
}
