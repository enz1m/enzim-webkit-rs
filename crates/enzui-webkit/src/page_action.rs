//! The seam between a resolved AccessKit activation and a native page-node
//! action.
//!

use crate::web::{ViewId, ViewRouter};

use crate::page_a11y::PageNodeKey;
use crate::page_delivery::PageA11yDelivery;

/// What happened when a resolved page action was dispatched through a
/// [`PageActionDispatch`] port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageActionDispatchOutcome {
    /// The port performed (or, on a non-native port, authorized and would
    /// perform) the action for the resolved node.
    Dispatched {
        /// The live view the action ran under.
        view: ViewId,
        /// The node the action operated.
        key: PageNodeKey,
    },
    /// The port refused to dispatch. The reason is human-readable so a host can
    /// surface it; a refusal is never silently treated as success.
    Refused {
        /// Why the dispatch was refused.
        reason: String,
    },
}

/// The production port a resolved page activation is dispatched through.
///
/// One method, so the drain/update path is identical whether the backing
/// implementation is a native `WebSession` (`crate::ffi::runtime`) or
/// the probe's feature-off router-checked port.
pub trait PageActionDispatch {
    /// Dispatch the action for the published node `key` on the live view.
    ///
    /// Implementations must consult `router`/`delivery` for liveness and
    /// generation so a stale or foreign id can never operate a control.
    fn dispatch_page_action(
        &mut self,
        router: &ViewRouter,
        live: ViewId,
        delivery: &PageA11yDelivery,
        key: &PageNodeKey,
    ) -> PageActionDispatchOutcome;
}
