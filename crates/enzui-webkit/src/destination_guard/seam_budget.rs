use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

// Canceled and timed-out callbacks can outlive their guards.
static GLOBAL: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(128)));

pub(super) fn global() -> Arc<Budget> {
    Arc::clone(&GLOBAL)
}

pub(super) struct Budget {
    active: AtomicUsize,
    limit: usize,
}

impl Budget {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    pub(super) fn acquire(self: &Arc<Self>) -> Option<Permit> {
        self.active
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()?;
        Some(Permit(self.clone()))
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

pub(super) struct Permit(Arc<Budget>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
