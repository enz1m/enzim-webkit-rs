//! Focus, Tab traversal, and IME-preedit ownership for embedded web pages.
//!
//! Tab is first offered to the page; a repeated Tab while its reply is pending releases focus to the toolkit. Generation checks discard replies invalidated by intervening events, and preedit ownership is exclusive.

use crate::web::view_id::Generation;

/// Which way a Tab traversal moves: Tab or Shift+Tab. A host maps its own
/// traversal type onto this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traversal {
    /// Tab: move to the next focusable control.
    Next,
    /// Shift+Tab: move to the previous focusable control.
    Previous,
}

impl Traversal {
    /// Whether this direction moves forward.
    #[must_use]
    pub const fn is_forward(self) -> bool {
        matches!(self, Self::Next)
    }
}

/// Who receives a key event considered by a web-view widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTarget {
    /// Routes the key to the embedded page.
    Page,
    /// Routes the key to the toolkit while no page element is focused.
    Toolkit,
    /// Leaves key routing to the toolkit because this widget is unfocused.
    None,
}

/// The page’s response to a forwarded [`Traversal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabReply {
    /// The page moved focus internally, so focus remains in the widget.
    Consumed,
    /// The page exhausted its internal order, so focus continues in the toolkit ring.
    Exhausted,
}

/// The observable result of a [`FocusHandoff`] transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffOutcome {
    /// The Tab was forwarded; toolkit traversal waits for a reply carrying `query`.
    ForwardedToPage {
        /// Direction forwarded, so the page knows which way to move.
        direction: Traversal,
        /// The generation the page's answer must carry to count.
        query: Generation,
    },
    /// Focus remains in the widget and the toolkit ring does not advance.
    StaysInWidget,
    /// Focus leaves the widget and the toolkit ring advances in `direction`.
    LeavesWidget {
        /// The direction the toolkit ring should move.
        direction: Traversal,
    },
    /// A stale page reply was discarded without changing state.
    StaleAnswerDiscarded,
    /// The event is not handled by this widget.
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusPhase {
    Unfocused,
    PageFocused,
    WidgetChrome,
    AwaitingPageTab {
        direction: Traversal,
        query: Generation,
    },
}

/// Coordinates page/toolkit focus and preedit ownership.
///
/// Pending Tab replies are invalidated by generation changes rather than wall-clock time.
#[derive(Debug, Clone)]
pub struct FocusHandoff {
    phase: FocusPhase,
    // Focus changes, routed non-Tab keys, and Tab presses advance this generation, invalidating outstanding Tab replies.
    generation: Generation,
    preedit: PreeditOwner,
}

impl Default for FocusHandoff {
    fn default() -> Self {
        Self::new()
    }
}

impl FocusHandoff {
    /// A fresh handoff for an unfocused widget with no preedit.
    #[must_use]
    pub fn new() -> FocusHandoff {
        FocusHandoff {
            phase: FocusPhase::Unfocused,
            generation: Generation::FIRST,
            preedit: PreeditOwner::None,
        }
    }

    /// Whether the widget currently holds toolkit focus.
    #[must_use]
    pub fn is_focused(&self) -> bool {
        !matches!(self.phase, FocusPhase::Unfocused)
    }

    /// Returns the current destination for routed key events.
    #[must_use]
    pub fn key_target(&self) -> KeyTarget {
        match self.phase {
            FocusPhase::Unfocused => KeyTarget::None,
            // A pending Tab reply does not surrender page key ownership.
            FocusPhase::PageFocused | FocusPhase::AwaitingPageTab { .. } => KeyTarget::Page,
            FocusPhase::WidgetChrome => KeyTarget::Toolkit,
        }
    }

    /// Who owns the IME preedit right now.
    #[must_use]
    pub fn preedit_owner(&self) -> PreeditOwner {
        self.preedit
    }

    /// Returns the current Tab-query generation.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    fn bump(&mut self) {
        self.generation = self.generation.next();
    }

    /// Records toolkit focus gain and routes keys according to `page_has_focusable`.
    pub fn focus_gained(&mut self, page_has_focusable: bool) -> HandoffOutcome {
        self.bump();
        self.phase = if page_has_focusable {
            FocusPhase::PageFocused
        } else {
            FocusPhase::WidgetChrome
        };
        HandoffOutcome::StaysInWidget
    }

    /// Records focus loss, invalidating pending Tab replies and cancelling any page preedit.
    pub fn focus_lost(&mut self) -> HandoffOutcome {
        self.bump();
        self.phase = FocusPhase::Unfocused;
        self.preedit = PreeditOwner::None;
        HandoffOutcome::StaysInWidget
    }

    /// Handles a non-Tab key and invalidates any pending Tab reply.
    pub fn key(&mut self) -> HandoffOutcome {
        match self.phase {
            FocusPhase::Unfocused => HandoffOutcome::Ignored,
            _ => {
                self.bump();
                HandoffOutcome::StaysInWidget
            }
        }
    }

    /// Forwards an initial Tab to the page; a repeated Tab while awaiting a reply releases focus in the new Tab’s direction.
    pub fn tab(&mut self, direction: Traversal) -> HandoffOutcome {
        match self.phase {
            FocusPhase::Unfocused => HandoffOutcome::Ignored,
            FocusPhase::AwaitingPageTab { .. } => {
                self.bump();
                self.phase = FocusPhase::Unfocused;
                self.preedit = PreeditOwner::None;
                HandoffOutcome::LeavesWidget { direction }
            }
            FocusPhase::PageFocused | FocusPhase::WidgetChrome => {
                self.bump();
                let query = self.generation;
                self.phase = FocusPhase::AwaitingPageTab { direction, query };
                HandoffOutcome::ForwardedToPage { direction, query }
            }
        }
    }

    /// Applies a page Tab reply when its generation is still current; stale replies are discarded, while exhausted replies release focus.
    pub fn page_tab_reply(&mut self, answered: Generation, reply: TabReply) -> HandoffOutcome {
        let FocusPhase::AwaitingPageTab { direction, query } = self.phase else {
            return HandoffOutcome::StaleAnswerDiscarded;
        };
        // The reply must match both the stored query and the live generation; intervening keys advance only the latter.
        if answered != query || query != self.generation {
            return HandoffOutcome::StaleAnswerDiscarded;
        }
        match reply {
            TabReply::Consumed => {
                // Resolving the outstanding query does not create a new generation.
                self.phase = FocusPhase::PageFocused;
                HandoffOutcome::StaysInWidget
            }
            TabReply::Exhausted => {
                self.phase = FocusPhase::Unfocused;
                self.preedit = PreeditOwner::None;
                HandoffOutcome::LeavesWidget { direction }
            }
        }
    }
}

/// The exclusive owner of the active IME preedit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreeditOwner {
    /// No active preedit.
    None,
    /// The embedded page owns the active preedit.
    Page,
    /// A native toolkit control owns the active preedit.
    Toolkit,
}

/// The reason an active preedit was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreeditCancel {
    /// The widget lost focus.
    FocusLost,
    /// The user pressed Escape.
    Escape,
    /// A pointer click landed elsewhere.
    ClickElsewhere,
}

/// The result of changing preedit ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreeditOutcome {
    /// The preedit is now owned by `owner`.
    Claimed {
        /// The new owner.
        owner: PreeditOwner,
    },
    /// Another owner already holds the preedit; ownership is unchanged.
    Refused {
        /// The owner that already holds the preedit.
        incumbent: PreeditOwner,
    },
    /// The preedit was cancelled; there is now no owner.
    Cancelled {
        /// Why it was cancelled.
        why: PreeditCancel,
    },
    /// The preedit was committed (composition finished); there is now no owner.
    Committed,
    /// Nothing to do (e.g. cancel with no active preedit).
    NoPreedit,
}

impl FocusHandoff {
    /// Claims preedit ownership for the page, refusing the claim if the toolkit owns it.
    pub fn page_claim_preedit(&mut self) -> PreeditOutcome {
        self.claim_preedit(PreeditOwner::Page)
    }

    /// Claims preedit ownership for the toolkit using first-claim-wins arbitration.
    pub fn toolkit_claim_preedit(&mut self) -> PreeditOutcome {
        self.claim_preedit(PreeditOwner::Toolkit)
    }

    fn claim_preedit(&mut self, who: PreeditOwner) -> PreeditOutcome {
        match self.preedit {
            PreeditOwner::None => {
                self.preedit = who;
                PreeditOutcome::Claimed { owner: who }
            }
            incumbent if incumbent == who => PreeditOutcome::Claimed { owner: who },
            incumbent => PreeditOutcome::Refused { incumbent },
        }
    }

    /// Cancels any active preedit for `why`, regardless of owner; returns [`PreeditOutcome::NoPreedit`] when none is active.
    pub fn cancel_preedit(&mut self, why: PreeditCancel) -> PreeditOutcome {
        if matches!(self.preedit, PreeditOwner::None) {
            return PreeditOutcome::NoPreedit;
        }
        self.preedit = PreeditOwner::None;
        PreeditOutcome::Cancelled { why }
    }

    /// Commits and clears the active preedit; returns [`PreeditOutcome::NoPreedit`] if none is active.
    pub fn commit_preedit(&mut self) -> PreeditOutcome {
        if matches!(self.preedit, PreeditOwner::None) {
            return PreeditOutcome::NoPreedit;
        }
        self.preedit = PreeditOwner::None;
        PreeditOutcome::Committed
    }
}
