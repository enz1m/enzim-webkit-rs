//! Generation-keyed identity for web-view instances.
//!
//! A logical slot survives recreation, and [`ViewRouter`] accepts only the identifier matching the slot's current generation.

/// A generation counter within one logical view slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Generation(pub u64);

impl Generation {
    /// The generation of a freshly-created view.
    pub const FIRST: Generation = Generation(0);

    /// Returns the following generation.
    #[must_use]
    pub fn next(self) -> Generation {
        Generation(self.0 + 1)
    }
}

/// Identifies one web-view instance by logical slot and generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ViewId {
    slot: u64,
    generation: Generation,
}

impl ViewId {
    /// The identity of a view newly created in `slot` at
    /// [`Generation::FIRST`].
    #[must_use]
    pub const fn new(slot: u64) -> ViewId {
        ViewId {
            slot,
            generation: Generation::FIRST,
        }
    }

    /// The stable logical slot.
    #[must_use]
    pub const fn slot(self) -> u64 {
        self.slot
    }

    /// The generation of this instance.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }
}

/// Tracks each slot’s live generation and rejects messages from other generations.
#[derive(Debug, Clone, Default)]
pub struct ViewRouter {
    live: std::collections::BTreeMap<u64, Generation>,
    // Retains each slot's last counter value so reopening derives its generation from the prior instance.
    last_minted: std::collections::BTreeMap<u64, Generation>,
}

impl ViewRouter {
    /// A router with no live views.
    #[must_use]
    pub fn new() -> ViewRouter {
        ViewRouter::default()
    }

    /// Creates or replaces the live view in `slot`, using [`Generation::FIRST`] for an unseen slot and [`Generation::next`] thereafter.
    pub fn create(&mut self, slot: u64) -> ViewId {
        let generation = match self.last_minted.get(&slot) {
            Some(g) => g.next(),
            None => Generation::FIRST,
        };
        self.last_minted.insert(slot, generation);
        self.live.insert(slot, generation);
        ViewId { slot, generation }
    }

    /// Recreates `slot` using the next counter value, or [`Generation::FIRST`] when the slot is unseen.
    pub fn recreate(&mut self, slot: u64) -> ViewId {
        self.create(slot)
    }

    /// The live [`ViewId`] for `slot`, if any.
    #[must_use]
    pub fn live_view(&self, slot: u64) -> Option<ViewId> {
        self.live
            .get(&slot)
            .map(|&generation| ViewId { slot, generation })
    }

    /// Returns `true` only when `id` exactly matches the slot’s current live generation.
    #[must_use]
    pub fn accepts(&self, id: ViewId) -> bool {
        self.live.get(&id.slot) == Some(&id.generation)
    }

    /// Removes the live view while retaining its generation tombstone; returns the removed id if present.
    pub fn destroy(&mut self, slot: u64) -> Option<ViewId> {
        self.live
            .remove(&slot)
            .map(|generation| ViewId { slot, generation })
    }

    /// The number of slots with a live view.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live.len()
    }
}
