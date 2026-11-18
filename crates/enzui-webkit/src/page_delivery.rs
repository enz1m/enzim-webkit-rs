//! Generation-owned delivery of a page's accessible tree, and routing of
//! assistive-technology actions back to the live page node.
//!
//! A tree or action naming a superseded generation is refused.
//!

use std::collections::HashMap;

use crate::web::{Generation, ViewId, ViewRouter};

use crate::page_a11y::{NativeAction, PageA11y, PageActionTarget, PageNodeKey};

/// What happened to an offered page-accessibility snapshot.
///
/// Deliberately not `#[non_exhaustive]`: a consumer must handle every
/// outcome explicitly. Adding a variant should break each caller so it decides
/// what the new case means, rather than letting a wildcard arm absorb a
/// rejection as if it were a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageDelivery {
    /// The snapshot belonged to the live generation and is now published.
    Accepted {
        /// The view it belongs to.
        view: ViewId,
        /// How many nodes it publishes.
        nodes: usize,
    },
    /// The snapshot came from a superseded generation and was discarded. The
    /// previously published tree, if any, is left untouched - a late arrival
    /// from a dead generation must not disturb the live view either.
    RejectedStale {
        /// The generation the snapshot claimed.
        offered: Generation,
        /// The slot's actual live generation.
        live: Generation,
    },
    /// The snapshot named a slot with no live view at all (never created, or
    /// already destroyed).
    RejectedNoLiveView {
        /// The slot named.
        slot: u64,
    },
}

/// The outcome of resolving an AT action against the published page tree.
///
/// Exhaustive for the same reason as [`PageDelivery`]: silently treating a new
/// refusal as "performed" is the failure this whole module exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageActionRoute {
    /// The action resolved to a live page node; perform it on this target.
    Routed {
        /// The view whose page owns the node.
        view: ViewId,
        /// Where to send the action, and which action to send.
        target: PageActionTarget,
    },
    /// No page tree is published for the live view, so nothing can be routed.
    NoPublishedPage,
    /// A tree is published, but it belongs to a superseded generation - the
    /// action arrived for a page that is gone.
    StaleView {
        /// The generation the published snapshot belongs to.
        published: Generation,
        /// The live generation asking.
        live: Generation,
    },
    /// The asking id is not the router's live view for its slot: the caller
    /// held a `ViewId` across a crash/close. Distinct from
    /// [`StaleView`](Self::StaleView), where the caller is live and the
    /// snapshot is old.
    ViewNotLive {
        /// The slot asked about.
        slot: u64,
        /// The generation the caller believed was live.
        asked: Generation,
        /// The generation that actually is, if the slot has a live view at all.
        live: Option<Generation>,
    },
    /// The live page has no node with that key (the page changed under the AT).
    UnknownNode {
        /// The key that resolved to nothing.
        key: PageNodeKey,
    },
    /// The node exists but advertises no routable action. Distinct from
    /// [`UnknownNode`](Self::UnknownNode): the tree is current and the node is
    /// real, it simply is not operable - surfaced so a caller can say so
    /// instead of silently doing nothing.
    NotActionable {
        /// The node's key.
        key: PageNodeKey,
    },
}

/// A router-checked page snapshot, owned so a widget can hold it across a
/// borrow, and unforgeable so a widget cannot be handed a tree that never
/// passed the delivery layer's ownership check.
///
/// # Why the widget takes this rather than a bare `PageA11y`
///
/// Accepting any [`PageA11y`] would let a host publish a dead page's cloned
/// controls into the host accessibility tree, bypassing the router and
/// generation guards. `PublishedPage` has no
/// public constructor: the only source is
/// [`PageA11yDelivery::published_page`], which runs the same router/generation
/// check as [`published`](PageA11yDelivery::published). A tree the widget
/// publishes therefore provably came through delivery for a live view.
///
/// # Deliberately not `Clone`
///
/// A witness is a single-use permission slip for one view at one moment. If it
/// were `Clone`, a host could mint one while a view is live, keep a copy, and
/// re-present it after the view was superseded - exactly the stale publication
/// the delivery check exists to stop. Being move-only, a witness is consumed by
/// the widget that accepts it ([`into_page`](Self::into_page)), and it carries
/// its [`view`](Self::view) so the receiving widget can refuse a witness minted
/// for a different view id (a different slot, or a generation held across a
/// crash).
#[derive(Debug, PartialEq)]
pub struct PublishedPage {
    view: ViewId,
    page: PageA11y,
}

impl PublishedPage {
    /// The view (slot + generation) this snapshot was checked for.
    #[must_use]
    pub fn view(&self) -> ViewId {
        self.view
    }

    /// The router-checked page tree.
    #[must_use]
    pub fn page(&self) -> &PageA11y {
        &self.page
    }

    /// Consume the witness into its owned tree.
    #[must_use]
    pub fn into_page(self) -> PageA11y {
        self.page
    }
}

/// Why a native `Action.DoAction` was refused by the action authority. Distinct
/// variants separate a non-live asking view, a missing native walk, a superseded
/// generation, or a node never recorded as natively actionable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeActionRefusal {
    /// The asking id is not the router's live view for its slot.
    ViewNotLive {
        /// The slot asked about.
        slot: u64,
        /// The generation the caller believed was live.
        asked: Generation,
        /// The generation that actually is, if the slot has a live view.
        live: Option<Generation>,
    },
    /// No native walk has ever installed an authority.
    NoNativeWalk,
    /// The installed authority belongs to a superseded generation.
    StaleWalk {
        /// The generation the authority was walked for.
        recorded: Generation,
        /// The live generation asking.
        live: Generation,
    },
    /// The key names no node the native walk recorded as actionable - the node
    /// is unknown, read-only, or was only ever present in a caller-supplied
    /// (inert) tree.
    NotNativelyActionable {
        /// The key that resolved to no native action.
        key: PageNodeKey,
    },
}

/// An authorized native action, resolved by
/// [`NativeActionAuthority::authorize`] against native-owned state.
///
/// Opaque and move-only: no public constructor and no [`Clone`]. Possession
/// of one is proof that this session's own native walk recorded this exact
/// object and index for the live view. The executor reads its fields straight
/// out and never consults a caller-supplied tree, so a cloned native address or
/// a reordered action list in an offered tree cannot influence what
/// `DoAction` receives.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedNativeAction {
    view: ViewId,
    key: PageNodeKey,
    action: NativeAction,
}

impl AuthorizedNativeAction {
    /// The live view this action was authorized for.
    #[must_use]
    pub fn view(&self) -> ViewId {
        self.view
    }

    /// The node key it was resolved from.
    #[must_use]
    pub fn key(&self) -> &PageNodeKey {
        &self.key
    }

    /// The native AT-SPI bus name to send `DoAction` to.
    #[must_use]
    pub fn bus_name(&self) -> &str {
        self.action.bus_name()
    }

    /// The native AT-SPI object path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.action.path()
    }

    /// The native, walk-validated action index.
    #[must_use]
    pub fn index(&self) -> usize {
        self.action.index()
    }
}

/// The native-owned authority over which page nodes may drive a real
/// `Action.DoAction`, keyed by node identity and stamped with the generation it
/// was walked for.
///
/// Populated only through `install`, whose sole caller is a
/// `WebSession` (`crate::ffi::runtime`)'s native delivery path. An
/// external [`AccessibleSource`](crate::page_a11y::AccessibleSource) cannot
/// reach it: it can offer a tree to [`PageA11yDelivery`] for display and
/// routing bookkeeping, but that path never touches the authority. So the
/// object and index that ultimately reach `DoAction` are always the ones this
/// session itself walked - never a caller's clone or reordering.
#[derive(Debug, Clone, Default)]
pub struct NativeActionAuthority {
    current: Option<(ViewId, HashMap<PageNodeKey, NativeAction>)>,
}

impl NativeActionAuthority {
    /// An authority with no native walk recorded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the native action targets harvested from a freshly walked live
    /// view. Crate-internal: the only non-test caller is the native delivery
    /// path (feature-on).
    #[cfg_attr(not(feature = "wpe"), allow(dead_code))]
    pub(crate) fn install(&mut self, view: ViewId, actions: HashMap<PageNodeKey, NativeAction>) {
        self.current = Some((view, actions));
    }

    /// Drop the recorded actions for `slot` (crash/close). Returns whether any
    /// were dropped.
    pub fn invalidate(&mut self, slot: u64) -> bool {
        match &self.current {
            Some((view, _)) if view.slot() == slot => {
                self.current = None;
                true
            }
            _ => false,
        }
    }

    /// The generation the authority was last walked for, if any.
    #[must_use]
    pub fn recorded_view(&self) -> Option<ViewId> {
        self.current.as_ref().map(|(v, _)| *v)
    }

    /// Authorize a native action for `key` under `live`.
    ///
    /// `Ok` only when the router still accepts `live`, the authority was
    /// installed for exactly `live` (same slot AND generation), and `key` names
    /// a node the native walk recorded as actionable. The returned address and
    /// index are the native ones; a caller-supplied tree is never consulted.
    ///
    /// # Errors
    ///
    /// A typed [`NativeActionRefusal`] for each independent reason to refuse.
    pub fn authorize(
        &self,
        router: &ViewRouter,
        live: ViewId,
        key: &PageNodeKey,
    ) -> Result<AuthorizedNativeAction, NativeActionRefusal> {
        if !router.accepts(live) {
            return Err(NativeActionRefusal::ViewNotLive {
                slot: live.slot(),
                asked: live.generation(),
                live: router.live_view(live.slot()).map(ViewId::generation),
            });
        }
        let Some((view, map)) = &self.current else {
            return Err(NativeActionRefusal::NoNativeWalk);
        };
        if *view != live {
            return Err(NativeActionRefusal::StaleWalk {
                recorded: view.generation(),
                live: live.generation(),
            });
        }
        match map.get(key) {
            Some(action) => Ok(AuthorizedNativeAction {
                view: live,
                key: key.clone(),
                action: action.clone(),
            }),
            None => Err(NativeActionRefusal::NotNativelyActionable { key: key.clone() }),
        }
    }
}

/// The host's owner of the live page-accessibility snapshot for one view slot.
///
/// Holds at most one snapshot, tagged with the [`ViewId`] that produced it.
#[derive(Debug, Clone, Default)]
pub struct PageA11yDelivery {
    current: Option<(ViewId, PageA11y)>,
}

impl PageA11yDelivery {
    /// An owner with nothing published.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer a snapshot produced for `view`.
    ///
    /// Accepted only when `router` says `view` is the live generation of its
    /// slot. A stale or orphaned snapshot is discarded without disturbing
    /// what is already published.
    pub fn offer(&mut self, router: &ViewRouter, view: ViewId, page: PageA11y) -> PageDelivery {
        if !router.accepts(view) {
            return match router.live_view(view.slot()) {
                Some(live) => PageDelivery::RejectedStale {
                    offered: view.generation(),
                    live: live.generation(),
                },
                None => PageDelivery::RejectedNoLiveView { slot: view.slot() },
            };
        }
        let nodes = page.count();
        self.current = Some((view, page));
        PageDelivery::Accepted { view, nodes }
    }

    /// Drop the published snapshot for `slot`, whatever generation it belongs
    /// to. Called on crash and on close.
    ///
    /// Returns whether anything was dropped. This is the *first* of the two
    /// guards; [`published`](Self::published) is the second and does not depend
    /// on this having been called.
    pub fn invalidate(&mut self, slot: u64) -> bool {
        match &self.current {
            Some((view, _)) if view.slot() == slot => {
                self.current = None;
                true
            }
            _ => false,
        }
    }

    /// Whether this owner retains no page snapshot at all.
    ///
    /// Unlike [`published`](Self::published), this observes physical retention,
    /// not merely whether routing currently authorizes publication. Destruction
    /// gates use it to prove the dead page tree was dropped rather than only
    /// hidden behind a destroyed router entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.current.is_none()
    }

    /// The snapshot to publish for `live`, or `None`.
    ///
    /// Returns `Some` only when `router` still considers `live` the live
    /// view of its slot *and* the held snapshot belongs to that exact id - same
    /// slot and same generation. Two independent reasons to refuse, neither of
    /// which depends on [`invalidate`](Self::invalidate) having been called.
    #[must_use]
    pub fn published(&self, router: &ViewRouter, live: ViewId) -> Option<&PageA11y> {
        // The caller's own id is checked first: a host that cached a `ViewId`
        // across a crash must not be able to read a page through it, however
        // faithfully the snapshot matches that dead id.
        if !router.accepts(live) {
            return None;
        }
        match &self.current {
            Some((view, page)) if *view == live => Some(page),
            _ => None,
        }
    }

    /// The router-checked snapshot to publish for `live`, as an owned,
    /// unforgeable [`PublishedPage`] a widget can hold across a borrow.
    ///
    /// `None` for the same two independent reasons as
    /// [`published`](Self::published): the caller's id is not the router's live
    /// view, or the held snapshot belongs to a different id. A widget can only
    /// ever receive a tree that passed both checks.
    #[must_use]
    pub fn published_page(&self, router: &ViewRouter, live: ViewId) -> Option<PublishedPage> {
        self.published(router, live).map(|page| PublishedPage {
            view: live,
            page: page.clone(),
        })
    }

    /// The [`ViewId`] the held snapshot belongs to, if any. For diagnostics and
    /// for the staleness report in [`route_action`](Self::route_action).
    #[must_use]
    pub fn published_view(&self) -> Option<ViewId> {
        self.current.as_ref().map(|(view, _)| *view)
    }

    /// Resolve an AT action on the page node identified by `key`.
    ///
    /// Every refusal is typed and distinct, because the five failures need
    /// different responses: the asking view is not live, no page at all, a page
    /// from a dead generation, a node that has gone, and a node that was never
    /// operable.
    #[must_use]
    pub fn route_action(
        &self,
        router: &ViewRouter,
        live: ViewId,
        key: &PageNodeKey,
    ) -> PageActionRoute {
        // Guard 3, first: an id the router no longer accepts can neither read
        // nor act, so a host holding a pre-crash `ViewId` cannot press a dead
        // page's button.
        if !router.accepts(live) {
            return PageActionRoute::ViewNotLive {
                slot: live.slot(),
                asked: live.generation(),
                live: router.live_view(live.slot()).map(ViewId::generation),
            };
        }
        let Some((view, page)) = &self.current else {
            return PageActionRoute::NoPublishedPage;
        };
        if *view != live {
            return PageActionRoute::StaleView {
                published: view.generation(),
                live: live.generation(),
            };
        }
        if page.node_for_key(key).is_none() {
            return PageActionRoute::UnknownNode { key: key.clone() };
        }
        match page.action_target(key) {
            Some(target) => PageActionRoute::Routed {
                view: *view,
                target,
            },
            None => PageActionRoute::NotActionable { key: key.clone() },
        }
    }
}
