//! Native Tab-focus observation shared by the WPE worker and focus handoff.
//!
//! `wpe_view_event` is fire-and-forget in WPE Platform 2.52: it returns `void`,
//! so dispatch success cannot say whether WebKit moved inside the document or
//! reached its embedding boundary. The controlled page therefore publishes a
//! monotonically increasing marker *after* each Tab dispatch has completed.
//! Comparing focus ids is valid only when that marker advanced. This matters at
//! the terminal element: WPE 2.52 keeps it focused in a headless toplevel, so an
//! old title and a processed boundary both otherwise look "unchanged".

use crate::web::focus::TabReply;

/// A page-authored acknowledgement of one completed Tab dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFocusToken {
    /// Monotonic marker committed by the page after the key's default action.
    pub marker: u64,
    /// Stable id of `document.activeElement`, or `None` outside the DOM ring.
    pub focused: Option<String>,
    /// Whether page script cancelled the Tab's default action.
    pub default_prevented: bool,
}

/// Parse the controlled page's `tf:<marker>:<prevented>:<id>|...` report.
///
/// Everything after the first `|` belongs to the page's ordinary diagnostic
/// title and is deliberately ignored. The focus id is controlled by the
/// fixture; `none` represents no focused DOM element.
#[must_use]
pub fn parse_native_focus_token(title: &str) -> Option<NativeFocusToken> {
    let header = title.strip_prefix("tf:")?.split('|').next()?;
    let mut fields = header.splitn(3, ':');
    let marker = fields.next()?.parse().ok()?;
    let default_prevented = match fields.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let focused = match fields.next()? {
        "" | "none" => None,
        id => Some(id.to_owned()),
    };
    Some(NativeFocusToken {
        marker,
        focused,
        default_prevented,
    })
}

/// What the native page did after an attempted Tab dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTabSignal {
    /// The event was refused before reaching this generation's WPE view.
    DispatchRejected,
    /// No causally newer page acknowledgement arrived. An unchanged old title
    /// must never be promoted into a boundary decision.
    NoCausalAck,
    /// Page script deliberately consumed the key with `preventDefault`.
    PreventedByPage,
    /// WebKit moved focus to a different element inside the document.
    MovedWithinPage,
    /// WebKit kept the same terminal element focused: WPE 2.52's headless
    /// embedding-boundary signal.
    BoundaryUnchanged,
    /// WebKit cleared document focus at the embedding boundary.
    BoundaryCleared,
}

impl NativeTabSignal {
    /// Convert a native observation into the answer consumed by
    /// `FocusHandoff`. Refused and unacknowledged dispatches are not page
    /// answers; the pending generation remains guarded and repeated Tab is the
    /// existing categorical escape.
    #[must_use]
    pub const fn reply(self) -> Option<TabReply> {
        match self {
            Self::DispatchRejected | Self::NoCausalAck => None,
            Self::PreventedByPage | Self::MovedWithinPage => Some(TabReply::Consumed),
            Self::BoundaryUnchanged | Self::BoundaryCleared => Some(TabReply::Exhausted),
        }
    }
}

/// Classify causally correlated focus tokens observed around one native Tab.
#[must_use]
pub fn observe_native_tab(
    dispatched: bool,
    before: Option<&NativeFocusToken>,
    after: Option<&NativeFocusToken>,
) -> NativeTabSignal {
    if !dispatched {
        return NativeTabSignal::DispatchRejected;
    }
    let (Some(before), Some(after)) = (before, after) else {
        return NativeTabSignal::NoCausalAck;
    };
    // Every dispatched Tab must advance the controlled page by exactly one.
    // Accepting merely "greater than" could attach a late acknowledgement from
    // a different key to this query after an observation gap.
    if before.marker.checked_add(1) != Some(after.marker) {
        return NativeTabSignal::NoCausalAck;
    }
    if after.default_prevented {
        NativeTabSignal::PreventedByPage
    } else if after.focused.is_none() {
        NativeTabSignal::BoundaryCleared
    } else if before.focused.as_deref() == after.focused.as_deref() {
        NativeTabSignal::BoundaryUnchanged
    } else {
        NativeTabSignal::MovedWithinPage
    }
}
